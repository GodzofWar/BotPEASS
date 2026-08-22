# BotPEASS

![](https://github.com/carlospolop/BotPEASS/raw/main/images/botpeas.png)

Use this bot to monitor new CVEs containing defined keywords and send alerts to Slack and/or Telegram.

CVE data comes from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities),
which is free and works without an API key.

Alerts are enriched with two more free, keyless sources:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — whether
  the CVE is *already being exploited in the wild*, with the federal remediation
  deadline and whether it is used in ransomware campaigns.
- **[EPSS](https://www.first.org/epss/)** — the probability the CVE will be exploited in
  the next 30 days, and how it ranks against every other CVE.

Together they separate the CVSS 9.8 that nobody will ever exploit from the 6.5 that is
already being weaponised.

## See it in action

Join the telegram group **[peass](https://t.me/peass)** to see the bot in action and be up to date with the latest privilege escalation vulnerabilities.

## Configure one for yourself

**Configuring your own BotPEASS** that notifies you about the new CVEs containing specific keywords is very easy!

- Fork this repo
- Modify the file `config/botpeas.yaml` and set your own keywords
- In the **github secrets** of your forked repo enter the following API keys:
    - **NVD_API_KEY**: (Optional) A [free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit from 5 to 50 requests per 30s. The bot works without one.
    - **SLACK_WEBHOOK**: (Optional) Set the slack webhook to send messages to your slack group
    - **DISCORD_WEBHOOK_URL**: (Optional) Set the discord webhook to send messages to your discord channel
    - **TELEGRAM_BOT_TOKEN** and **TELEGRAM_CHAT_ID**: (Optional) Your Telegram bot token and the chat_id to send the messages to
    - **PUSHOVER_DEVICE_NAME PUSHOVER_USER_KEY PUSHOVER_TOKEN**: (Optional) Set your key and token to receive pushover notifications.
    - **NTFY_URL**: (Optional) Set the URL to send the notifications to ntfy server.
    - **NTFY_TOPIC**: (Optional) Set the topic to send the notifications to ntfy server.
    - **NTFY_AUTH**: (Optional) Set the auth token for the ntfy server.

- Check `.github/workflows/botpeas.yaml` and configure the cron (*once every 8 hours by default*)

*Note that the slack, telegram, discord and ntfy.sh configurations are optional, but if you don't set any of them you won't receive any notifications anywhere*

## Configuration options

`config/botpeas.yaml` also accepts:

| Key | Default | Meaning |
| --- | --- | --- |
| `ALL_VALID` | `no` | Notify on every CVE, ignoring the keyword lists |
| `MAX_BACKFILL_DAYS` | `7` | If the bot has been down a while, replay at most this many days instead of flooding your channels. `null` disables the limit |
| `LOOKBACK_DAYS` | `1` | How far back to look on the very first run, when there is no saved state |
| `ENABLE_KEV` | `yes` | Flag CVEs listed in the CISA KEV catalog |
| `ENABLE_EPSS` | `yes` | Attach EPSS exploitation probabilities |
| `MIN_CVSS` | `null` | Drop CVEs below this CVSS base score |
| `MIN_EPSS` | `null` | Drop CVEs below this EPSS probability (`0.1` = 10%) |
| `KEV_ONLY` | `no` | Alert only on CVEs in the KEV catalog |
| `ALWAYS_ALERT_KEV` | `yes` | Let KEV entries through regardless of `MIN_CVSS`/`MIN_EPSS` |
| `SKIP_UNSCORED` | `no` | Drop CVEs that have no score yet when a threshold is set |

### A note on unscored CVEs

Newly published CVEs frequently have no CVSS or EPSS score for days. By default they
**pass** the thresholds rather than being hidden — a monitor that suppresses the newest
CVEs defeats its own purpose. If you would rather trade that recall for less noise, set
`SKIP_UNSCORED: yes`.

### Suggested starting point

Alert on everything your keywords match, but let anything actively exploited through
no matter what:

```yaml
MIN_EPSS: 0.05          # at least a 5% chance of exploitation
ALWAYS_ALERT_KEV: yes   # ...unless CISA says it is already happening
```

## Running it locally

```bash
python3 -m pip install -r requirements.txt

# See what would be sent, without notifying anyone or touching the saved state
python3 botpeas.py --dry-run

# Ignore the saved state and look back a fixed number of days
python3 botpeas.py --dry-run --since-days 3
```

`--dry-run` is the quickest way to confirm your keywords match what you expect
before you point the bot at a live channel.

Other flags: `--config PATH` and `--state PATH` to point at alternative files.

## Running the tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/
```

The tests stub out the NVD API, so they need no network access and no API key.
