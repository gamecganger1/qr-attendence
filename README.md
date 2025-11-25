# Attendance QR Project

A small Flask-based attendance management application that uses QR codes for student attendance. This README explains how to set up, run, and explore the project found at the repository root.

## Features
- Flask web application with routes and templates.
- QR code generation and storage in `static/qrcodes/`.
- Separate dashboards / login pages for admin, teacher, and student.
- Lightweight SQLite-style instance DB (project contains `instance/` folder).

## Requirements
- Python 3.8+ recommended
- See `requirements.txt` for Python package dependencies

## Quick setup (PowerShell on Windows)
Open PowerShell in the project root (`c:\Users\karti\Desktop\Manjeet_project`) and run:

```powershell
# create virtual environment
python -m venv venv
# activate virtualenv in PowerShell
venv\Scripts\Activate.ps1
# install dependencies
pip install -r requirements.txt
```

## Running the app
There are two common ways to run the app. Use whichever fits your workflow.

1) Run via the project entry script (recommended if `run.py` is configured to call app.run):

```powershell
python run.py
```

2) Run with Flask development server (set environment variable for Flask):

```powershell
$env:FLASK_APP = "run.py"
# optional: set to development
$env:FLASK_ENV = "development"
flask run --host=0.0.0.0
```

If your `run.py` already calls `app.run(...)`, then `python run.py` is sufficient.

## Project layout
- `run.py` — application entry script
- `requirements.txt` — Python dependencies
- `app/` — main Flask package
  - `__init__.py` — app factory / initialization
  - `models.py` — database models
  - `routes.py` — HTTP routes and view logic
  - `static/` — static assets
    - `CSS/style.css` — styles
    - `qrcodes/` — generated QR code images
    - `reports/` — generated attendance reports
  - `templates/` — Jinja2 HTML templates (login, dashboards, reports, etc.)
- `instance/` — instance-specific files (database file, config)
- `scripts/` — helper scripts (e.g., `add_device_token_column.py`)

## Important files to inspect
- `app/routes.py` — routes and endpoints for login, dashboard, QR display, registration, and report generation.
- `app/models.py` — DB model definitions and relationships.
- `templates/` — edit these to modify UI.

## Common tasks
- Generate QR codes: The app stores QR images (look under `app/static/qrcodes/`). See the code path that writes files in `app/routes.py`.
- Database: If the app uses SQLite in `instance/`, ensure `instance/` is writable. If migration scripts are not present, scripts in `scripts/` may modify schema.

## Troubleshooting
- If missing packages: re-run `pip install -r requirements.txt` inside the activated venv.
- If port 5000 in use: pass `--port <n>` to `flask run`, or modify `run.py` to use another port.
- If templates not found: ensure working directory is project root and `app` package can be imported.

## Notes for contributors
- Keep changes small and focused. Update `requirements.txt` when adding dependencies.
- Prefer adding unit tests for new features.

## Next steps / enhancements
- Add database migrations (Flask-Migrate/Alembic) for schema changes.
- Add unit tests and CI workflow.
- Add short developer docs for major flows (creating users, generating QR codes, exporting reports).

## License
Add your chosen license here (e.g., MIT) — this repository currently has no license file.


---

File created: `README.md` — basic project overview, setup, run instructions, and developer notes.
