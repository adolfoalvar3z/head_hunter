:: filepath: /d:/asalvarez/Documents/Auditorias/py/header_hunter/setup_and_run.bat
@echo off
REM Create virtual environment
python -m venv venv

REM Activate virtual environment
call venv\Scripts\activate

REM Install required packages
pip install -r requirements.txt

REM Run the script
python header_hunter.py

REM Deactivate virtual environment
deactivate
