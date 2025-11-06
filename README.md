Bind Zone Manager

This is a minimal Flask-based web app to manage hostnames, aliases and IP addresses and generate BIND zone files using templates in `templates/`.

Quick start (development):

1. Create a virtualenv and install Flask:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install Flask
```

2. Run the app (port 80 by default; use PORT env var to override):

```bash
PORT=8000 python app.py
```

3. Open http://localhost:8000/ (or port 80 if run as root)

Notes:
- Data is stored in `data/hosts.json`.
- Generated zone files are written to `generated/` when you press "Generate".
- Templates are read from `templates/`. The app looks for `$ORIGIN` in the template and appends managed records under that origin.
 - Data is stored in SQLite at `data/hosts.db`.
 - Generated zone files are written to `generated/` when you press "Generate".
 - Templates are read from `templates/`. The app looks for `$ORIGIN` in the template and appends managed records under that origin.
