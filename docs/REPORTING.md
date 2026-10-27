# Reporting and Evidence

| Output | Data |
|---|---|
| events.jsonl | Normalized frame Evidence |
| alerts.jsonl | All rule events |
| run.log and debug.jsonl | Status and bounded debug detail |
| telemetry.jsonl | Counters, lag, and sensor GPS |
| session.json | Config and saved state |
| networks.jsonl | Full final AP history |
| proofs/ | Rule frames, hashes, and replay |
| report.html, report.pdf, report.json | Human and technical reports |
| report-hashes.json | Report SHA-256 values |

HTML has 10 sections, charts, AP search, and technical data.
Simple View and Technical View use the same record.
The report works offline. It needs no chart service.
PDF includes the full JSON as an attachment.
Missing values stay missing. RSSI gaps stay blank.
A saved report shows SAVED DATA.

Logs save every 5 seconds. HTML and JSON save every 30 seconds.
These are target intervals. Slow storage can delay a save.
PDF saves at stop. A hard stop can leave an older snapshot.
No end record means the stop cause is unknown.
The 256 MiB limit covers incoming Evidence. Exports need extra space.
Debug detail has a separate cap. Omitted detail rows are counted.
Capture stops at the configured packet or Evidence limit.

Check a saved bundle:

```sh
python3 tools/verify_proofs.py /path/to/session
```

Keep events.jsonl, alerts.jsonl, session.json, and proofs/ together.
The verifier checks exact rows, file hashes, config, and current rule replay.
A hash checks byte changes. It does not prove radio origin.
A changed full bundle has no trusted signature.
Same-code replay is not independent field validation.
