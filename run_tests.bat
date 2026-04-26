@echo off
REM Run tests with coverage. Use this to see coverage %% before or after spin-up.
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=html --cov-fail-under=0 -v
echo.
echo HTML report: htmlcov\index.html
echo.
echo UI tests (headless): behave
pause
