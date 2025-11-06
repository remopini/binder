Bind Zone Manager

This is a minimal Flask-based web app to manage hostnames, aliases and IP addresses and generate BIND zone files.

Quick start (development):

1. Install Flask and sqlite:

```bash
apt install python3-flask sqlite
```

2. Run the app (port 80 by default; use PORT env var to override):

```bash
PORT=8000 python app.py
```

3. Open http://host-ip-or-name:8000/ (or port 80 if run as root)

Notes:
- Data is stored using SQLite at `data/hosts.db`.
- Zone files are written to the directory set in the setting when you make any changes.
- Whenever zone files are written, BIND will automatically be restarted (see config options on the settings page)