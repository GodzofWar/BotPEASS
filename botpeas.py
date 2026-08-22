#!/usr/bin/env python3
"""BotPEASS - monitor new/modified CVEs matching configured keywords and alert on them.

Data comes from the NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0),
which is free and works without an API key. Setting NVD_API_KEY raises the rate limit
from 5 to 50 requests per 30s window.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterator

import requests
import yaml

BASE_DIR = pathlib.Path(__file__).parent.absolute()
CVES_JSON_PATH = BASE_DIR / "output" / "botpeas.json"
KEYWORDS_CONFIG_PATH = BASE_DIR / "config" / "botpeas.yaml"

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PARAM_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000"
# The NVD API refuses date ranges wider than 120 days, so long backfills are chunked.
NVD_MAX_RANGE_DAYS = 120
NVD_RESULTS_PER_PAGE = 2000
# NVD asks for ~6s between requests without a key; an API key allows a far higher rate.
NVD_SLEEP_NO_KEY = 6.0
NVD_SLEEP_WITH_KEY = 0.6

HTTP_TIMEOUT = 60
MAX_RETRIES = 4
BACKOFF_BASE = 2
RETRYABLE_STATUS = {403, 408, 429, 500, 502, 503, 504}

SUMMARY_LIMIT = 500
MAX_CPES_SHOWN = 10
MAX_REFS_SHOWN = 5
MAX_EXPLOITS_SHOWN = 20

# Preference order when a CVE carries several scoring systems.
CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

DEFAULT_LOOKBACK_DAYS = 1
DEFAULT_MAX_BACKFILL_DAYS = 7

ALL_VALID = False
DESCRIPTION_KEYWORDS_I: list = []
DESCRIPTION_KEYWORDS: list = []
PRODUCT_KEYWORDS_I: list = []
PRODUCT_KEYWORDS: list = []
MAX_BACKFILL_DAYS = DEFAULT_MAX_BACKFILL_DAYS
LOOKBACK_DAYS = DEFAULT_LOOKBACK_DAYS

LAST_NEW_CVE = datetime.datetime.utcnow() - datetime.timedelta(days=DEFAULT_LOOKBACK_DAYS)
LAST_MODIFIED_CVE = datetime.datetime.utcnow() - datetime.timedelta(days=DEFAULT_LOOKBACK_DAYS)


class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


# NVD names the two date-range filters differently from our internal field names.
NVD_DATE_PARAMS = {
    Time_Type.PUBLISHED: ("pubStartDate", "pubEndDate"),
    Time_Type.LAST_MODIFIED: ("lastModStartDate", "lastModEndDate"),
}


################## LOAD CONFIGURATIONS ####################

def load_keywords(config_path=KEYWORDS_CONFIG_PATH):
    ''' Load keywords from config file '''

    global ALL_VALID
    global DESCRIPTION_KEYWORDS_I, DESCRIPTION_KEYWORDS
    global PRODUCT_KEYWORDS_I, PRODUCT_KEYWORDS
    global MAX_BACKFILL_DAYS, LOOKBACK_DAYS

    with open(config_path, 'r') as yaml_file:
        keywords_config = yaml.safe_load(yaml_file) or {}
        print(f"Loaded keywords: {keywords_config}")
        ALL_VALID = keywords_config.get("ALL_VALID", False)
        DESCRIPTION_KEYWORDS_I = keywords_config.get("DESCRIPTION_KEYWORDS_I") or []
        DESCRIPTION_KEYWORDS = keywords_config.get("DESCRIPTION_KEYWORDS") or []
        PRODUCT_KEYWORDS_I = keywords_config.get("PRODUCT_KEYWORDS_I") or []
        PRODUCT_KEYWORDS = keywords_config.get("PRODUCT_KEYWORDS") or []
        MAX_BACKFILL_DAYS = keywords_config.get("MAX_BACKFILL_DAYS", DEFAULT_MAX_BACKFILL_DAYS)
        LOOKBACK_DAYS = keywords_config.get("LOOKBACK_DAYS", DEFAULT_LOOKBACK_DAYS)


def load_lasttimes(state_path=CVES_JSON_PATH):
    ''' Load lasttimes from json file '''

    global LAST_NEW_CVE, LAST_MODIFIED_CVE

    default = datetime.datetime.utcnow() - datetime.timedelta(days=LOOKBACK_DAYS)
    LAST_NEW_CVE = default
    LAST_MODIFIED_CVE = default

    try:
        with open(state_path, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = parse_cve_time(cves_time["LAST_NEW_CVE"])
            LAST_MODIFIED_CVE = parse_cve_time(cves_time["LAST_MODIFIED_CVE"])

    except Exception as e:  # If error, just keep the default date (today - LOOKBACK_DAYS)
        print(f"ERROR, using default last times.\n{e}")

    # A long-dormant bot would otherwise replay months of CVEs in a single burst.
    LAST_NEW_CVE = clamp_backfill(LAST_NEW_CVE, "LAST_NEW_CVE")
    LAST_MODIFIED_CVE = clamp_backfill(LAST_MODIFIED_CVE, "LAST_MODIFIED_CVE")

    print(f"Last new cve: {LAST_NEW_CVE}")
    print(f"Last modified cve: {LAST_MODIFIED_CVE}")


def clamp_backfill(last_time: datetime.datetime, label: str) -> datetime.datetime:
    ''' Refuse to replay more than MAX_BACKFILL_DAYS worth of CVEs at once '''

    if MAX_BACKFILL_DAYS is None:
        return last_time

    oldest = datetime.datetime.utcnow() - datetime.timedelta(days=MAX_BACKFILL_DAYS)
    if last_time < oldest:
        print(f"WARNING: {label} ({last_time}) is older than MAX_BACKFILL_DAYS "
              f"({MAX_BACKFILL_DAYS}); clamping to {oldest} to avoid an alert flood.")
        return oldest

    return last_time


def update_lasttimes(state_path=CVES_JSON_PATH):
    ''' Save lasttimes in json file '''

    pathlib.Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)


################## NVD API ####################

def parse_cve_time(value: str) -> datetime.datetime:
    ''' Parse the timestamp formats NVD and the state file use, as naive UTC '''

    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1]

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except ValueError:
            continue

    raise ValueError(f"Unrecognised timestamp: {value!r}")


def nvd_get(params: dict, session=None) -> dict:
    ''' GET the NVD API with retries and exponential backoff '''

    session = session or requests
    api_key = os.getenv('NVD_API_KEY')
    headers = {"apiKey": api_key} if api_key else {}

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            r = session.get(NVD_API_URL, params=params, headers=headers, timeout=HTTP_TIMEOUT)

            if r.status_code == 200:
                return r.json()

            if r.status_code not in RETRYABLE_STATUS:
                raise RuntimeError(f"NVD returned HTTP {r.status_code}: {r.text[:200]}")

            last_error = f"HTTP {r.status_code}"

        except (requests.RequestException, ValueError) as e:
            last_error = str(e)

        if attempt < MAX_RETRIES - 1:
            delay = BACKOFF_BASE * (2 ** attempt)
            print(f"NVD request failed ({last_error}); retrying in {delay}s")
            time.sleep(delay)

    raise RuntimeError(f"NVD request failed after {MAX_RETRIES} attempts: {last_error}")


def date_windows(start: datetime.datetime, end: datetime.datetime) -> Iterator[tuple]:
    ''' Split [start, end] into chunks the NVD API will accept '''

    span = datetime.timedelta(days=NVD_MAX_RANGE_DAYS)
    while start < end:
        chunk_end = min(start + span, end)
        yield start, chunk_end
        start = chunk_end


def get_cves(tt_filter: Time_Type, start: datetime.datetime, end: datetime.datetime,
             session=None) -> list:
    ''' Retrieve every CVE in the given window, following pagination '''

    start_param, end_param = NVD_DATE_PARAMS[tt_filter]
    sleep_between = NVD_SLEEP_WITH_KEY if os.getenv('NVD_API_KEY') else NVD_SLEEP_NO_KEY

    results = []
    seen_ids = set()
    first_request = True

    for window_start, window_end in date_windows(start, end):
        start_index = 0

        while True:
            if not first_request:
                time.sleep(sleep_between)
            first_request = False

            params = {
                start_param: window_start.strftime(NVD_PARAM_TIME_FORMAT),
                end_param: window_end.strftime(NVD_PARAM_TIME_FORMAT),
                "resultsPerPage": NVD_RESULTS_PER_PAGE,
                "startIndex": start_index,
            }

            payload = nvd_get(params, session=session)
            vulnerabilities = payload.get("vulnerabilities") or []

            for vulnerability in vulnerabilities:
                if not vulnerability.get("cve"):
                    continue

                normalized = normalize_cve(vulnerability["cve"])
                # NVD date ranges are inclusive at both ends, so a CVE sitting on a
                # chunk boundary comes back in two windows. Alert on it once.
                if normalized["id"] in seen_ids:
                    continue

                seen_ids.add(normalized["id"])
                results.append(normalized)

            total = payload.get("totalResults", 0)
            # Fall back to the batch size we actually got: a resultsPerPage of 0
            # alongside a non-empty page would never advance the cursor.
            start_index += payload.get("resultsPerPage") or len(vulnerabilities)

            if start_index >= total or not vulnerabilities:
                break

    return results


def normalize_cve(cve: dict) -> dict:
    ''' Flatten an NVD 2.0 record into the shape the filters and renderers expect '''

    score, severity = extract_cvss(cve)

    return {
        "id": cve.get("id", ""),
        "cvss": score,
        "cvss_severity": severity,
        "Published": normalize_timestamp(cve.get("published", "")),
        "last-modified": normalize_timestamp(cve.get("lastModified", "")),
        "summary": extract_description(cve),
        "vulnerable_configuration": extract_cpes(cve),
        "references": extract_references(cve),
    }


def normalize_timestamp(value: str) -> str:
    ''' Render an NVD timestamp in the state file's format, tolerating junk '''

    if not value:
        return ""

    try:
        return parse_cve_time(value).strftime(TIME_FORMAT)
    except ValueError:
        return value


def extract_description(cve: dict) -> str:
    ''' Prefer the English description, fall back to whatever is available '''

    descriptions = cve.get("descriptions") or []
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")

    return descriptions[0].get("value", "") if descriptions else ""


def extract_cvss(cve: dict) -> tuple:
    ''' Return (base score, severity) from the most recent scoring system present '''

    metrics = cve.get("metrics") or {}

    for key in CVSS_METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue

        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = primary.get("cvssData") or {}
        score = cvss_data.get("baseScore")

        if score is None:
            continue

        # CVSS v2 keeps the severity beside cvssData rather than inside it.
        severity = cvss_data.get("baseSeverity") or primary.get("baseSeverity")
        return float(score), severity

    return None, None


def extract_cpes(cve: dict) -> list:
    ''' Collect the vulnerable CPE strings, de-duplicated and order preserved '''

    configurations = cve.get("configurations") or []
    if isinstance(configurations, dict):  # Older 2.0 responses wrapped nodes in a dict
        configurations = [configurations]

    cpes = []
    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria")
                if criteria and criteria not in cpes:
                    cpes.append(criteria)

    return cpes


def extract_references(cve: dict) -> list:
    ''' Collect reference URLs, de-duplicated and order preserved '''

    urls = []
    for reference in cve.get("references") or []:
        url = reference.get("url")
        if url and url not in urls:
            urls.append(url)

    return urls


################## SEARCH CVES ####################

def get_new_cves(session=None) -> list:
    ''' Get CVEs that are new '''

    global LAST_NEW_CVE

    now = datetime.datetime.utcnow()
    cves = get_cves(Time_Type.PUBLISHED, LAST_NEW_CVE, now, session=session)
    filtered_cves, new_last_time = filter_cves(cves, LAST_NEW_CVE, Time_Type.PUBLISHED)
    LAST_NEW_CVE = new_last_time

    return filtered_cves


def get_modified_cves(session=None) -> list:
    ''' Get CVEs that have been modified '''

    global LAST_MODIFIED_CVE

    now = datetime.datetime.utcnow()
    cves = get_cves(Time_Type.LAST_MODIFIED, LAST_MODIFIED_CVE, now, session=session)
    filtered_cves, new_last_time = filter_cves(cves, LAST_MODIFIED_CVE, Time_Type.LAST_MODIFIED)
    LAST_MODIFIED_CVE = new_last_time

    return filtered_cves


def filter_cves(cves: list, last_time: datetime.datetime, tt_filter: Time_Type) -> tuple:
    ''' Filter by time and keywords the given list of CVEs '''

    filtered_cves = []
    new_last_time = last_time

    for cve in cves:
        raw_time = cve.get(tt_filter.value)
        if not raw_time:
            continue

        try:
            cve_time = parse_cve_time(raw_time)
        except ValueError:
            print(f"Skipping {cve.get('id')}: unparsable {tt_filter.value} {raw_time!r}")
            continue

        if cve_time > last_time:
            if ALL_VALID or is_summ_keyword_present(cve["summary"]) or \
                    is_prod_keyword_present(str(cve["vulnerable_configuration"])):

                filtered_cves.append(cve)

        if cve_time > new_last_time:
            new_last_time = cve_time

    return filtered_cves, new_last_time


def is_summ_keyword_present(summary: str):
    ''' Given the summary check if any keyword is present '''

    return any(w in summary for w in DESCRIPTION_KEYWORDS) or \
        any(w.lower() in summary.lower() for w in DESCRIPTION_KEYWORDS_I)


def is_prod_keyword_present(products: str):
    ''' Given the products check if any keyword is present '''

    return any(w in products for w in PRODUCT_KEYWORDS) or \
        any(w.lower() in products.lower() for w in PRODUCT_KEYWORDS_I)


def search_exploits(cve: str) -> list:
    ''' Given a CVE it will search for public exploits to abuse it '''

    # TODO: replace the retired Vulners integration with KEV/EPSS/PoC-in-GitHub lookups.
    return []


#################### GENERATE MESSAGES #########################

@dataclass(frozen=True)
class Format:
    ''' Per-sink escaping, emphasis and length rules '''

    escape: Callable[[str], str]
    bold: Callable[[str], str]
    limit: int


def escape_none(text: str) -> str:
    return text


def escape_slack(text: str) -> str:
    ''' Slack mrkdwn only reserves the three HTML entities '''

    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


TELEGRAM_SPECIAL_CHARS = r"_*[]()~`>#+-=|{}.!\\"


def escape_telegram(text: str) -> str:
    ''' Escape every character Telegram MarkdownV2 reserves '''

    return "".join("\\" + c if c in TELEGRAM_SPECIAL_CHARS else c for c in text)


DISCORD_SPECIAL_CHARS = r"*_~`|>[]()\\"


def escape_discord(text: str) -> str:
    ''' Escape the Discord markdown control characters '''

    return "".join("\\" + c if c in DISCORD_SPECIAL_CHARS else c for c in text)


SLACK_FORMAT = Format(escape=escape_slack, bold=lambda s: f"*{s}*", limit=2900)
TELEGRAM_FORMAT = Format(escape=escape_telegram, bold=lambda s: f"*{s}*", limit=4000)
DISCORD_FORMAT = Format(escape=escape_discord, bold=lambda s: f"**{s}**", limit=1900)
NTFY_FORMAT = Format(escape=escape_none, bold=lambda s: s, limit=4000)
PUSHOVER_FORMAT = Format(escape=escape_none, bold=lambda s: s, limit=1000)


def truncate(message: str, limit: int) -> str:
    ''' Keep a message inside the sink's hard length limit '''

    if len(message) <= limit:
        return message

    # A single "…" rather than "...", because a dot is a reserved MarkdownV2
    # character and would need escaping to survive Telegram.
    cut = message[:limit - 1]

    # Never end on a dangling escape: a trailing backslash makes Telegram reject
    # the whole message.
    cut = cut.rstrip("\\")

    return cut + "…"


def format_cvss(cve_data: dict) -> str:
    ''' Human readable score, since NVD leaves unscored CVEs without metrics '''

    score = cve_data.get("cvss")
    if score is None:
        return "Unknown"

    severity = cve_data.get("cvss_severity")
    return f"{score} ({severity})" if severity else str(score)


def generate_new_cve_message(cve_data: dict, fmt: Format = NTFY_FORMAT) -> str:
    ''' Generate new CVE message for the given sink format '''

    e, b = fmt.escape, fmt.bold

    summary = cve_data["summary"]
    if len(summary) > SUMMARY_LIMIT:
        summary = summary[:SUMMARY_LIMIT] + "..."

    # Every literal below is escaped too, not just the CVE data: Telegram rejects
    # the whole message over one bare "(", and the labels carry punctuation.
    lines = [
        f"🚨  {b(e(cve_data['id']))}  🚨",
        f"🔮  {b(e('CVSS'))}{e(': ')}{e(format_cvss(cve_data))}",
        f"📅  {b(e('Published'))}{e(': ')}{e(cve_data['Published'])}",
        f"📓  {b(e('Summary'))}{e(': ')}{e(summary)}",
    ]

    if cve_data["vulnerable_configuration"]:
        vulnerable = ", ".join(cve_data["vulnerable_configuration"][:MAX_CPES_SHOWN])
        lines.append(f"🔓  {b(e('Vulnerable'))}"
                     f"{e(f' (limit {MAX_CPES_SHOWN}): ')}{e(vulnerable)}")

    if cve_data["references"]:
        lines.append("")
        lines.append(f"🟢 ℹ️  {b(e('More information'))}{e(f' (limit {MAX_REFS_SHOWN})')}")
        lines.extend(e(url) for url in cve_data["references"][:MAX_REFS_SHOWN])

    return "\n".join(lines)


def generate_modified_cve_message(cve_data: dict, fmt: Format = NTFY_FORMAT) -> str:
    ''' Generate modified CVE message for the given sink format '''

    e, b = fmt.escape, fmt.bold

    modified = cve_data["last-modified"].split("T")[0]
    published = cve_data["Published"].split("T")[0]

    tail = (f" ({format_cvss(cve_data)}) was modified on {modified} "
            f"(originally published {published})")

    return f"📣 {b(e(cve_data['id']))}{e(tail)}"


def generate_public_expls_message(public_expls: list, fmt: Format = NTFY_FORMAT) -> str:
    ''' Given the list of public exploits, generate the message '''

    if not public_expls:
        return ""

    e, b = fmt.escape, fmt.bold
    header = f"😈  {b(e('Public Exploits'))}{e(f' (limit {MAX_EXPLOITS_SHOWN})')}  😈"

    return header + "\n" + "\n".join(e(url) for url in public_expls[:MAX_EXPLOITS_SHOWN])


def build_message(cve_data: dict, public_expls: list, fmt: Format, is_new: bool) -> str:
    ''' Render one CVE for one sink, exploits included, within the sink's limit '''

    if is_new:
        message = generate_new_cve_message(cve_data, fmt)
    else:
        message = generate_modified_cve_message(cve_data, fmt)

    expls_message = generate_public_expls_message(public_expls, fmt)
    if expls_message:
        message = message + "\n" + expls_message

    return truncate(message, fmt.limit)


#################### SEND MESSAGES #########################

def send_slack_message(cve_data: dict, public_expls: list, is_new: bool):
    ''' Send a message to the slack group '''

    slack_url = os.getenv('SLACK_WEBHOOK')

    if not slack_url:
        print("SLACK_WEBHOOK wasn't configured in the secrets!")
        return

    message = build_message(cve_data, public_expls, SLACK_FORMAT, is_new)

    json_params = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            },
            {
                "type": "divider"
            }
        ]
    }

    r = requests.post(slack_url, json=json_params, timeout=HTTP_TIMEOUT)
    if r.status_code >= 300:
        print(f"ERROR SENDING TO SLACK: HTTP {r.status_code} {r.text[:200]}")


def send_telegram_message(cve_data: dict, public_expls: list, is_new: bool):
    ''' Send a message to the telegram group '''

    telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

    if not telegram_bot_token:
        print("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        return

    if not telegram_chat_id:
        print("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        return

    message = build_message(cve_data, public_expls, TELEGRAM_FORMAT, is_new)

    # POST with a JSON body: the summary and reference URLs routinely contain
    # characters that a GET query string would truncate or mangle.
    r = requests.post(
        f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage",
        json={
            "chat_id": telegram_chat_id,
            "text": message,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True,
        },
        timeout=HTTP_TIMEOUT,
    )

    resp = r.json()
    if not resp.get('ok'):
        print(f"ERROR SENDING TO TELEGRAM: {cve_data['id']} {resp.get('description')}")


def send_discord_message(cve_data: dict, public_expls: list, is_new: bool):
    ''' Send a message to the discord channel webhook '''

    discord_webhook_url = os.getenv('DISCORD_WEBHOOK_URL')

    if not discord_webhook_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return

    message = build_message(cve_data, public_expls, DISCORD_FORMAT, is_new)

    r = requests.post(discord_webhook_url, json={"content": message}, timeout=HTTP_TIMEOUT)
    if r.status_code >= 300:
        print(f"ERROR SENDING TO DISCORD: HTTP {r.status_code} {r.text[:200]}")


def send_pushover_message(cve_data: dict, public_expls: list, is_new: bool):
    ''' Send a message to the pushover device '''

    pushover_device_name = os.getenv('PUSHOVER_DEVICE_NAME')
    pushover_user_key = os.getenv('PUSHOVER_USER_KEY')
    pushover_token = os.getenv('PUSHOVER_TOKEN')

    if not pushover_device_name:
        print("PUSHOVER_DEVICE_NAME wasn't configured in the secrets!")
        return
    if not pushover_user_key:
        print("PUSHOVER_USER_KEY wasn't configured in the secrets!")
        return
    if not pushover_token:
        print("PUSHOVER_TOKEN wasn't configured in the secrets!")
        return

    message = build_message(cve_data, public_expls, PUSHOVER_FORMAT, is_new)

    data = {
        "token": pushover_token,
        "user": pushover_user_key,
        "message": message,
        "device": pushover_device_name,
    }

    r = requests.post("https://api.pushover.net/1/messages.json", data=data,
                      timeout=HTTP_TIMEOUT)
    if r.status_code >= 300:
        print(f"ERROR SENDING TO PUSHOVER: HTTP {r.status_code} {r.text[:200]}")


def send_ntfy_message(cve_data: dict, public_expls: list, is_new: bool):
    ''' Send a message to the ntfy.sh topic '''

    ntfy_url = os.getenv('NTFY_URL')
    ntfy_topic = os.getenv('NTFY_TOPIC')
    ntfy_auth = os.getenv('NTFY_AUTH')

    if not ntfy_url:
        print("NTFY_URL wasn't configured in the environment variables!")
        return

    if not ntfy_topic:
        print("NTFY_TOPIC wasn't configured in the environment variables!")
        return

    message = build_message(cve_data, public_expls, NTFY_FORMAT, is_new)

    full_ntfy_url = f"{ntfy_url.rstrip('/')}/{ntfy_topic}"

    headers = {
        "Title": "New CVE Alert",
        "Priority": "high",
    }

    if ntfy_auth:
        headers["Authorization"] = ntfy_auth

    response = requests.post(full_ntfy_url, data=message.encode('utf-8'), headers=headers,
                             timeout=HTTP_TIMEOUT)

    if response.status_code == 200:
        print(f"Notification sent to ntfy.sh topic: {ntfy_topic}")
    else:
        print(f"Failed to send notification to ntfy.sh. Status code: "
              f"{response.status_code}, Response: {response.text[:200]}")


SINKS = (
    send_slack_message,
    send_telegram_message,
    send_discord_message,
    send_pushover_message,
    send_ntfy_message,
)


def notify(cve_data: dict, public_expls: list, is_new: bool, dry_run: bool = False):
    ''' Fan a CVE out to every sink; one broken sink must not abort the run '''

    if dry_run:
        print("-" * 60)
        print(build_message(cve_data, public_expls, NTFY_FORMAT, is_new))
        return

    for sink in SINKS:
        try:
            sink(cve_data, public_expls, is_new)
        except Exception as e:
            print(f"ERROR in {sink.__name__} for {cve_data['id']}: {e}")


#################### MAIN #########################

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Monitor new CVEs matching your keywords.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the CVEs that would be sent without notifying anyone "
                             "or updating the saved state.")
    parser.add_argument("--since-days", type=float, default=None,
                        help="Ignore the saved state and look back this many days instead.")
    parser.add_argument("--config", default=KEYWORDS_CONFIG_PATH,
                        help="Path to the keywords YAML config.")
    parser.add_argument("--state", default=CVES_JSON_PATH,
                        help="Path to the JSON file holding the last-run timestamps.")
    return parser.parse_args(argv)


def main(argv=None):
    global LAST_NEW_CVE, LAST_MODIFIED_CVE

    args = parse_args(argv)

    # Load configured keywords
    load_keywords(args.config)

    # Start loading time of last checked ones
    if args.since_days is not None:
        since = datetime.datetime.utcnow() - datetime.timedelta(days=args.since_days)
        LAST_NEW_CVE = since
        LAST_MODIFIED_CVE = since
        print(f"Overriding saved state, looking back to {since}")
    else:
        load_lasttimes(args.state)

    # Find and publish new CVEs
    new_cves = get_new_cves()

    new_cves_ids = [ncve['id'] for ncve in new_cves]
    print(f"New CVEs discovered: {new_cves_ids}")

    for new_cve in new_cves:
        public_exploits = search_exploits(new_cve['id'])
        notify(new_cve, public_exploits, is_new=True, dry_run=args.dry_run)

    # Find and publish modified CVEs
    modified_cves = get_modified_cves()

    modified_cves = [mcve for mcve in modified_cves if mcve['id'] not in new_cves_ids]
    modified_cves_ids = [mcve['id'] for mcve in modified_cves]
    print(f"Modified CVEs discovered: {modified_cves_ids}")

    for modified_cve in modified_cves:
        public_exploits = search_exploits(modified_cve['id'])
        notify(modified_cve, public_exploits, is_new=False, dry_run=args.dry_run)

    # Update last times
    if args.dry_run:
        print(f"Dry run: not saving state (would be LAST_NEW_CVE={LAST_NEW_CVE}, "
              f"LAST_MODIFIED_CVE={LAST_MODIFIED_CVE})")
    else:
        update_lasttimes(args.state)

    return 0


if __name__ == "__main__":
    sys.exit(main())
