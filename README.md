HawkEye
=======

HawkEye is a Windows desktop EDR-style monitor with a Tkinter UI. It scans files,
monitors network connections, and surfaces suspicious activity with a local
quarantine workflow.

Features
--------
- File scan with heuristic scoring and SHA-256 hashing
- Network monitoring and alerting
- Persistence checks (scheduled tasks, services, registry)
- Quarantine management UI

Requirements
------------
- Python 3.11+ recommended
- Windows (uses Win32 APIs and registry)

Setup
-----
1) Create a virtual environment
2) Install dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run
---
```powershell
python main.py
```

Build (PyInstaller)
-------------------
```powershell
build.bat
```

Notes
-----
Runtime files like `hawkeye_events.jsonl` and `hawkeye_config.json` are ignored
by Git and generated on first run.
