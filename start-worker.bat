@echo off
title PhishKiller Celery Worker
cd /d "%~dp0"
echo Starting PhishKiller Celery worker...
echo Press Ctrl+C to stop.
echo.
.venv\Scripts\celery -A phishkiller.celery_app worker -l info -P solo -B -Q celery,feeds,downloads,analysis,certstream
pause
