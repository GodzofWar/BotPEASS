import datetime
import json
import pathlib
import re

import pytest

import botpeas


FIXTURE = pathlib.Path(__file__).parent / "nvd_sample.json"


@pytest.fixture
def nvd_payload():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture
def polkit(nvd_payload):
    return botpeas.normalize_cve(nvd_payload["vulnerabilities"][0]["cve"])


@pytest.fixture
def coffee(nvd_payload):
    return botpeas.normalize_cve(nvd_payload["vulnerabilities"][1]["cve"])


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class FakeSession:
    ''' Records the params of each call and replays a queue of responses '''

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(params)
        return self.responses.pop(0)


##################### TIMESTAMP PARSING #####################

@pytest.mark.parametrize("raw,expected", [
    ("2022-01-28T19:15:09.777", datetime.datetime(2022, 1, 28, 19, 15, 9, 777000)),
    ("2022-01-28T19:15:09", datetime.datetime(2022, 1, 28, 19, 15, 9)),
    ("2022-01-28T19:15:09Z", datetime.datetime(2022, 1, 28, 19, 15, 9)),
    ("2022-01-28T19:15", datetime.datetime(2022, 1, 28, 19, 15)),
])
def test_parse_cve_time_accepts_nvd_and_state_formats(raw, expected):
    assert botpeas.parse_cve_time(raw) == expected


def test_parse_cve_time_rejects_junk():
    with pytest.raises(ValueError):
        botpeas.parse_cve_time("not-a-date")


##################### NVD NORMALIZATION #####################

def test_normalize_prefers_english_description(polkit):
    assert polkit["summary"].startswith("A local privilege escalation vulnerability")


def test_normalize_prefers_cvss_v31_over_v2(polkit):
    assert polkit["cvss"] == 7.8
    assert polkit["cvss_severity"] == "HIGH"


def test_normalize_reads_v2_severity_from_outside_cvss_data():
    cve = {
        "id": "CVE-0000-0000",
        "metrics": {"cvssMetricV2": [
            {"type": "Primary", "cvssData": {"baseScore": 7.2}, "baseSeverity": "HIGH"}
        ]},
    }
    assert botpeas.extract_cvss(cve) == (7.2, "HIGH")


def test_normalize_handles_missing_metrics(coffee):
    assert coffee["cvss"] is None
    assert botpeas.format_cvss(coffee) == "Unknown"


def test_normalize_deduplicates_cpes(polkit):
    assert polkit["vulnerable_configuration"] == [
        "cpe:2.3:a:polkit_project:polkit:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
    ]


def test_normalize_deduplicates_references(polkit):
    assert polkit["references"] == [
        "https://example.org/advisory?id=1&x=2",
        "https://example.org/patch-1.0_final(rev2)",
    ]


def test_normalize_reformats_timestamps(polkit):
    assert polkit["Published"] == "2022-01-28T19:15:09"
    assert polkit["last-modified"] == "2023-11-07T03:39:52"


def test_normalize_survives_an_empty_record():
    normalized = botpeas.normalize_cve({})
    assert normalized["id"] == ""
    assert normalized["references"] == []
    assert normalized["vulnerable_configuration"] == []


def test_extract_cpes_accepts_dict_shaped_configurations():
    cve = {"configurations": {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:x:y"}]}]}}
    assert botpeas.extract_cpes(cve) == ["cpe:2.3:a:x:y"]


##################### DATE WINDOWS + PAGINATION #####################

def test_date_windows_splits_ranges_wider_than_the_nvd_limit():
    start = datetime.datetime(2024, 1, 1)
    end = datetime.datetime(2024, 12, 31)
    windows = list(botpeas.date_windows(start, end))

    assert len(windows) == 4
    assert windows[0][0] == start
    assert windows[-1][1] == end
    # Windows must be contiguous so nothing falls between them.
    for earlier, later in zip(windows, windows[1:]):
        assert earlier[1] == later[0]
    for window_start, window_end in windows:
        assert (window_end - window_start).days <= botpeas.NVD_MAX_RANGE_DAYS


def test_date_windows_is_empty_when_start_is_not_before_end():
    now = datetime.datetime(2024, 1, 1)
    assert list(botpeas.date_windows(now, now)) == []


def test_get_cves_follows_pagination(monkeypatch, nvd_payload):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)

    third = {"cve": {"id": "CVE-2024-11111", "published": "2024-12-03T00:00:00.000",
                     "lastModified": "2024-12-03T00:00:00.000",
                     "descriptions": [{"lang": "en", "value": "third"}]}}

    page_one = FakeResponse({"totalResults": 3, "resultsPerPage": 2,
                             "vulnerabilities": nvd_payload["vulnerabilities"]})
    page_two = FakeResponse({"totalResults": 3, "resultsPerPage": 1,
                             "vulnerabilities": [third]})
    session = FakeSession([page_one, page_two])

    cves = botpeas.get_cves(
        botpeas.Time_Type.PUBLISHED,
        datetime.datetime(2024, 12, 1),
        datetime.datetime(2024, 12, 5),
        session=session,
    )

    assert len(cves) == 3
    assert [c["startIndex"] for c in session.calls] == [0, 2]


def test_get_cves_uses_the_right_date_parameters_per_time_type():
    session = FakeSession([FakeResponse({"totalResults": 0, "resultsPerPage": 0,
                                         "vulnerabilities": []})])
    botpeas.get_cves(botpeas.Time_Type.LAST_MODIFIED,
                     datetime.datetime(2024, 12, 1),
                     datetime.datetime(2024, 12, 5),
                     session=session)

    assert "lastModStartDate" in session.calls[0]
    assert "lastModEndDate" in session.calls[0]
    assert "pubStartDate" not in session.calls[0]


def test_nvd_get_retries_retryable_statuses_then_succeeds(monkeypatch):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)
    session = FakeSession([
        FakeResponse({}, status_code=503),
        FakeResponse({"ok": True}, status_code=200),
    ])

    assert botpeas.nvd_get({}, session=session) == {"ok": True}
    assert len(session.calls) == 2


def test_nvd_get_does_not_retry_a_client_error(monkeypatch):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)
    session = FakeSession([FakeResponse({}, status_code=404)])

    with pytest.raises(RuntimeError):
        botpeas.nvd_get({}, session=session)
    assert len(session.calls) == 1


def test_nvd_get_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)
    session = FakeSession([FakeResponse({}, status_code=503)] * botpeas.MAX_RETRIES)

    with pytest.raises(RuntimeError):
        botpeas.nvd_get({}, session=session)
    assert len(session.calls) == botpeas.MAX_RETRIES


##################### FILTERING #####################

def test_filter_cves_tracks_the_modified_field_not_the_published_one(polkit, monkeypatch):
    ''' The old code compared last-modified CVEs against their published date '''

    monkeypatch.setattr(botpeas, "ALL_VALID", True)

    # Published 2022, modified 2023: a bot last run in 2023-01 must still see it.
    last_run = datetime.datetime(2023, 1, 1)
    filtered, new_last = botpeas.filter_cves([polkit], last_run,
                                             botpeas.Time_Type.LAST_MODIFIED)

    assert [c["id"] for c in filtered] == ["CVE-2021-4034"]
    assert new_last == datetime.datetime(2023, 11, 7, 3, 39, 52)


def test_filter_cves_excludes_entries_at_or_before_the_last_run(polkit, monkeypatch):
    monkeypatch.setattr(botpeas, "ALL_VALID", True)

    last_run = datetime.datetime(2023, 11, 7, 3, 39, 52)
    filtered, new_last = botpeas.filter_cves([polkit], last_run,
                                             botpeas.Time_Type.LAST_MODIFIED)

    assert filtered == []
    assert new_last == last_run


def test_filter_cves_applies_description_keywords(polkit, coffee, monkeypatch):
    monkeypatch.setattr(botpeas, "ALL_VALID", False)
    monkeypatch.setattr(botpeas, "DESCRIPTION_KEYWORDS_I", ["Privilege Escalation"])
    monkeypatch.setattr(botpeas, "DESCRIPTION_KEYWORDS", [])
    monkeypatch.setattr(botpeas, "PRODUCT_KEYWORDS_I", [])
    monkeypatch.setattr(botpeas, "PRODUCT_KEYWORDS", [])

    filtered, _ = botpeas.filter_cves([polkit, coffee], datetime.datetime(2020, 1, 1),
                                      botpeas.Time_Type.PUBLISHED)

    assert [c["id"] for c in filtered] == ["CVE-2021-4034"]


def test_filter_cves_applies_product_keywords(polkit, coffee, monkeypatch):
    monkeypatch.setattr(botpeas, "ALL_VALID", False)
    monkeypatch.setattr(botpeas, "DESCRIPTION_KEYWORDS_I", [])
    monkeypatch.setattr(botpeas, "DESCRIPTION_KEYWORDS", [])
    monkeypatch.setattr(botpeas, "PRODUCT_KEYWORDS_I", ["redhat"])
    monkeypatch.setattr(botpeas, "PRODUCT_KEYWORDS", [])

    filtered, _ = botpeas.filter_cves([polkit, coffee], datetime.datetime(2020, 1, 1),
                                      botpeas.Time_Type.PUBLISHED)

    assert [c["id"] for c in filtered] == ["CVE-2021-4034"]


def test_filter_cves_skips_records_with_unparsable_timestamps(monkeypatch):
    monkeypatch.setattr(botpeas, "ALL_VALID", True)
    broken = {"id": "CVE-X", "Published": "garbage", "summary": "",
              "vulnerable_configuration": []}

    filtered, new_last = botpeas.filter_cves([broken], datetime.datetime(2020, 1, 1),
                                             botpeas.Time_Type.PUBLISHED)

    assert filtered == []
    assert new_last == datetime.datetime(2020, 1, 1)


##################### BACKFILL CLAMP #####################

def test_clamp_backfill_limits_a_long_dormant_state(monkeypatch):
    monkeypatch.setattr(botpeas, "MAX_BACKFILL_DAYS", 7)
    ancient = datetime.datetime(2020, 1, 1)

    clamped = botpeas.clamp_backfill(ancient, "LAST_NEW_CVE")

    assert clamped > ancient
    assert (datetime.datetime.utcnow() - clamped).days <= 7


def test_clamp_backfill_leaves_a_recent_state_alone(monkeypatch):
    monkeypatch.setattr(botpeas, "MAX_BACKFILL_DAYS", 7)
    recent = datetime.datetime.utcnow() - datetime.timedelta(hours=3)

    assert botpeas.clamp_backfill(recent, "LAST_NEW_CVE") == recent


def test_clamp_backfill_can_be_disabled(monkeypatch):
    monkeypatch.setattr(botpeas, "MAX_BACKFILL_DAYS", None)
    ancient = datetime.datetime(2020, 1, 1)

    assert botpeas.clamp_backfill(ancient, "LAST_NEW_CVE") == ancient


##################### STATE ROUND TRIP #####################

def test_lasttimes_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(botpeas, "MAX_BACKFILL_DAYS", None)
    state = tmp_path / "botpeas.json"

    monkeypatch.setattr(botpeas, "LAST_NEW_CVE", datetime.datetime(2024, 12, 5, 5, 15, 0))
    monkeypatch.setattr(botpeas, "LAST_MODIFIED_CVE", datetime.datetime(2024, 12, 4, 1, 2, 3))
    botpeas.update_lasttimes(state)

    botpeas.load_lasttimes(state)
    assert botpeas.LAST_NEW_CVE == datetime.datetime(2024, 12, 5, 5, 15, 0)
    assert botpeas.LAST_MODIFIED_CVE == datetime.datetime(2024, 12, 4, 1, 2, 3)


def test_load_lasttimes_falls_back_when_the_state_file_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(botpeas, "LOOKBACK_DAYS", 1)
    monkeypatch.setattr(botpeas, "MAX_BACKFILL_DAYS", 7)

    botpeas.load_lasttimes(tmp_path / "does-not-exist.json")

    assert (datetime.datetime.utcnow() - botpeas.LAST_NEW_CVE).days <= 1


##################### MESSAGE RENDERING #####################

def test_telegram_escapes_every_reserved_character():
    """Telegram rejects the whole message if one reserved char is left bare."""

    reserved = "_*[]()~`>#+-=|{}.!"
    escaped = botpeas.escape_telegram(reserved)

    # Every reserved character comes back preceded by a single backslash.
    assert escaped == "".join("\\" + c for c in reserved)
    # A backslash in the source text is escaped too.
    assert botpeas.escape_telegram("a\\b") == "a\\\\b"
    # Ordinary text is untouched.
    assert botpeas.escape_telegram("CVE 2021 polkit") == "CVE 2021 polkit"


def test_telegram_message_escapes_content_but_not_bold_markers(polkit):
    message = botpeas.build_message(polkit, [], botpeas.TELEGRAM_FORMAT, is_new=True)

    # The structural bold the template adds stays live markup...
    assert "*CVE\\-2021\\-4034*" in message
    assert "*Summary*" in message
    # ...while reserved characters coming from CVE data are escaped.
    assert "polkit\\_project" in message
    assert "escalation vulnerability was found on polkit's pkexec" in message
    # Asterisks from CVE data (CPE wildcards) are escaped, so once those are
    # removed the only asterisks left are the template's bold delimiters.
    assert message.count(r"\*") == 15  # the CPE wildcards, all escaped
    live_asterisks = message.replace(r"\*", "").count("*")
    assert live_asterisks == 12  # six bold spans, two delimiters each


def test_slack_message_escapes_html_entities(polkit):
    polkit = dict(polkit, summary="a < b & c > d")
    message = botpeas.build_message(polkit, [], botpeas.SLACK_FORMAT, is_new=True)

    assert "a &lt; b &amp; c &gt; d" in message
    assert "*CVE-2021-4034*" in message


def test_discord_uses_double_asterisk_bold(polkit):
    message = botpeas.build_message(polkit, [], botpeas.DISCORD_FORMAT, is_new=True)

    assert "**CVE-2021-4034**" in message


def test_plain_sinks_do_not_escape(polkit):
    message = botpeas.build_message(polkit, [], botpeas.NTFY_FORMAT, is_new=True)

    assert "CVE-2021-4034" in message
    assert "\\" not in message


@pytest.mark.parametrize("fmt", [
    botpeas.SLACK_FORMAT,
    botpeas.TELEGRAM_FORMAT,
    botpeas.DISCORD_FORMAT,
    botpeas.NTFY_FORMAT,
    botpeas.PUSHOVER_FORMAT,
])
def test_messages_stay_within_each_sink_limit(fmt):
    ''' Discord rejects >2000 chars and Pushover >1024, so long CVEs must be truncated '''

    huge = {
        "id": "CVE-2024-00001",
        "cvss": 9.8,
        "cvss_severity": "CRITICAL",
        "Published": "2024-12-05T05:15:00",
        "last-modified": "2024-12-05T05:15:00",
        "summary": "x" * 5000,
        "vulnerable_configuration": [f"cpe:2.3:a:vendor:product{i}" * 5 for i in range(50)],
        "references": [f"https://example.org/very/long/reference/path/{i}" for i in range(50)],
    }

    message = botpeas.build_message(huge, [f"https://exploit/{i}" for i in range(50)],
                                    fmt, is_new=True)

    assert len(message) <= fmt.limit


def test_modified_message_mentions_both_dates(polkit):
    message = botpeas.build_message(polkit, [], botpeas.NTFY_FORMAT, is_new=False)

    assert "2023-11-07" in message
    assert "2022-01-28" in message


def test_exploit_block_is_omitted_when_there_are_none(polkit):
    message = botpeas.build_message(polkit, [], botpeas.NTFY_FORMAT, is_new=True)

    assert "Public Exploits" not in message


def test_exploit_block_appears_exactly_once(polkit):
    ''' The old Discord sink appended the exploit block twice '''

    message = botpeas.build_message(polkit, ["https://exploit.example/poc"],
                                    botpeas.NTFY_FORMAT, is_new=True)

    assert message.count("https://exploit.example/poc") == 1
    assert message.count("Public Exploits") == 1


def test_notify_dry_run_sends_nothing(polkit, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(botpeas, "SINKS", (lambda *a, **k: called.append(1),))

    botpeas.notify(polkit, [], is_new=True, dry_run=True)

    assert called == []
    assert "CVE-2021-4034" in capsys.readouterr().out


def test_notify_survives_a_failing_sink(polkit, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise RuntimeError("webhook down")

    delivered = []
    monkeypatch.setattr(botpeas, "SINKS", (broken, lambda *a, **k: delivered.append(1)))

    botpeas.notify(polkit, [], is_new=True)

    assert delivered == [1]
    assert "webhook down" in capsys.readouterr().out


##################### END TO END #####################

def test_main_dry_run_reports_matches_without_sending_or_saving(
        tmp_path, monkeypatch, nvd_payload, capsys):
    ''' Full run against a stubbed NVD, exercising config, filtering and rendering '''

    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)

    config = tmp_path / "botpeas.yaml"
    config.write_text(
        "ALL_VALID: no\n"
        "DESCRIPTION_KEYWORDS_I:\n- privilege escalation\n"
        "DESCRIPTION_KEYWORDS: []\n"
        "PRODUCT_KEYWORDS_I: []\n"
        "PRODUCT_KEYWORDS: []\n"
        "MAX_BACKFILL_DAYS: 3650\n"
        "LOOKBACK_DAYS: 1\n"
    )

    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "LAST_NEW_CVE": "2020-01-01T00:00:00",
        "LAST_MODIFIED_CVE": "2020-01-01T00:00:00",
    }))

    monkeypatch.setattr(botpeas, "nvd_get", lambda params, session=None: {
        "totalResults": 2, "resultsPerPage": 2,
        "vulnerabilities": nvd_payload["vulnerabilities"],
    })

    sent = []
    monkeypatch.setattr(botpeas, "SINKS", (lambda *a, **k: sent.append(a[0]["id"]),))

    exit_code = botpeas.main(["--dry-run", "--config", str(config), "--state", str(state)])
    out = capsys.readouterr().out

    assert exit_code == 0
    # The polkit CVE matches the keyword; the coffee machine one does not.
    assert "CVE-2021-4034" in out
    assert "CVE-2024-99999" not in out
    # Dry run must not deliver anything or overwrite the saved state.
    assert sent == []
    assert json.loads(state.read_text())["LAST_NEW_CVE"] == "2020-01-01T00:00:00"


def test_main_saves_state_and_delivers_when_not_a_dry_run(
        tmp_path, monkeypatch, nvd_payload):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)

    config = tmp_path / "botpeas.yaml"
    config.write_text("ALL_VALID: yes\nMAX_BACKFILL_DAYS: 3650\nLOOKBACK_DAYS: 1\n")

    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "LAST_NEW_CVE": "2020-01-01T00:00:00",
        "LAST_MODIFIED_CVE": "2020-01-01T00:00:00",
    }))

    monkeypatch.setattr(botpeas, "nvd_get", lambda params, session=None: {
        "totalResults": 2, "resultsPerPage": 2,
        "vulnerabilities": nvd_payload["vulnerabilities"],
    })

    sent = []
    monkeypatch.setattr(botpeas, "SINKS", (lambda cve, expls, is_new: sent.append(
        (cve["id"], is_new)),))

    botpeas.main(["--config", str(config), "--state", str(state)])

    # Both CVEs are new; neither should also be announced as modified.
    assert sorted(sent) == [("CVE-2021-4034", True), ("CVE-2024-99999", True)]

    saved = json.loads(state.read_text())
    assert saved["LAST_NEW_CVE"] == "2024-12-05T05:15:00"
    assert saved["LAST_MODIFIED_CVE"] == "2024-12-05T05:15:00"


def test_main_since_days_overrides_saved_state(tmp_path, monkeypatch, nvd_payload):
    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)

    config = tmp_path / "botpeas.yaml"
    config.write_text("ALL_VALID: yes\n")

    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "LAST_NEW_CVE": "2030-01-01T00:00:00",
        "LAST_MODIFIED_CVE": "2030-01-01T00:00:00",
    }))

    captured = {}

    def fake_get(params, session=None):
        captured.update(params)
        return {"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}

    monkeypatch.setattr(botpeas, "nvd_get", fake_get)
    monkeypatch.setattr(botpeas, "SINKS", ())

    botpeas.main(["--dry-run", "--since-days", "2",
                  "--config", str(config), "--state", str(state)])

    # The window must start ~2 days ago, not at the far-future saved state.
    start = botpeas.parse_cve_time(captured["lastModStartDate"])
    assert 1 < (datetime.datetime.utcnow() - start).total_seconds() / 86400 < 3


def test_get_cves_deduplicates_across_window_boundaries(monkeypatch, nvd_payload):
    ''' NVD ranges are inclusive at both ends, so boundary CVEs repeat per window '''

    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)
    monkeypatch.setattr(botpeas, "nvd_get", lambda params, session=None: {
        "totalResults": 2, "resultsPerPage": 2,
        "vulnerabilities": nvd_payload["vulnerabilities"],
    })

    # A 300-day span is split into three windows, each replaying the same CVEs.
    cves = botpeas.get_cves(botpeas.Time_Type.PUBLISHED,
                            datetime.datetime(2024, 1, 1),
                            datetime.datetime(2024, 10, 27))

    assert [c["id"] for c in cves] == ["CVE-2021-4034", "CVE-2024-99999"]


def test_get_cves_terminates_when_the_api_reports_no_page_size(monkeypatch, nvd_payload):
    ''' resultsPerPage of 0 on a non-empty page must not spin forever '''

    monkeypatch.setattr(botpeas.time, "sleep", lambda _: None)
    calls = []

    def fake_get(params, session=None):
        calls.append(params)
        if len(calls) > 10:
            raise AssertionError("get_cves did not terminate")
        return {"totalResults": 2, "resultsPerPage": 0,
                "vulnerabilities": nvd_payload["vulnerabilities"]}

    monkeypatch.setattr(botpeas, "nvd_get", fake_get)

    cves = botpeas.get_cves(botpeas.Time_Type.PUBLISHED,
                            datetime.datetime(2024, 12, 1),
                            datetime.datetime(2024, 12, 5))

    assert len(calls) == 1
    assert len(cves) == 2


def test_truncate_never_leaves_a_dangling_escape():
    ''' A trailing backslash would make Telegram reject the whole message '''

    # Craft a message whose cut point lands immediately after an escape.
    message = "a" * 18 + "\\" + "." + "b" * 20
    truncated = botpeas.truncate(message, 20)

    assert len(truncated) <= 20
    assert not truncated.rstrip("…").endswith("\\")


def test_truncate_uses_a_non_reserved_ellipsis():
    ''' "..." would need MarkdownV2 escaping; the single glyph does not '''

    truncated = botpeas.truncate("x" * 100, 20)

    assert truncated.endswith("…")
    assert "..." not in truncated
    for char in truncated:
        assert char not in botpeas.TELEGRAM_SPECIAL_CHARS or char == "x"


def test_truncate_leaves_short_messages_untouched():
    assert botpeas.truncate("short", 20) == "short"


@pytest.mark.parametrize("is_new", [True, False])
def test_telegram_message_has_no_bare_reserved_characters(polkit, is_new):
    """Telegram rejects the entire message over a single unescaped reserved char."""

    message = botpeas.build_message(polkit, ["https://exploit.example/poc-1.0(x)"],
                                    botpeas.TELEGRAM_FORMAT, is_new=is_new)

    # Drop every escaped pair, then the bold delimiters the template emits.
    remaining = re.sub(r"\\.", "", message, flags=re.S).replace("*", "")

    reserved = set("_[]()~`>#+-=|{}.!\\")
    assert [c for c in remaining if c in reserved] == []


def test_telegram_labels_with_punctuation_are_escaped(polkit):
    """The (limit N) labels are literals, but Telegram still needs them escaped."""

    message = botpeas.build_message(polkit, [], botpeas.TELEGRAM_FORMAT, is_new=True)

    assert "\\(limit 10\\)" in message
    assert "(limit 10)" not in message
