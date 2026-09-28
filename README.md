# Intrusion Detection System Integrated with Cloud Logging

B.Tech Computer Science and Engineering project: a lightweight, rule-based Intrusion Detection System (IDS) integrated with cloud logging.

## Students
- Pratyush Tiwari — 2402221530091
- Saurabh Vishwakarma — 2402221530114
- Guide: Mr. Sushil Chabra
- ITS Engineering College, Greater Noida
- Session: 2026–2027

## Architecture
Event Source → Log Collector → Parser/Normalizer → IDS Rule Engine → Alert Generator → Cloud Logging → Dashboard/Query

## Detection Rules
- Repeated failed-login detection
- Restricted-resource access detection
- Suspicious test-signature detection
- Severity classification

## Technology
Python 3, JSON/local logging, rule-based detection, optional cloud logging integration, Git/GitHub.

## Structure
- `src/ids.py` — IDS rule engine and demo runner
- `src/log_parser.py` — event normalization
- `src/cloud_logging_adapter.py` — cloud-log record adapter
- `data/sample_events.json` — synthetic demonstration events
- `docs/project-notes.md` — presentation and security notes

## Run
`python src/ids.py`

The demo uses synthetic/authorized events only. Never scan, attack, or monitor systems without explicit authorization. Never commit passwords, API keys, tokens, or cloud credentials.
