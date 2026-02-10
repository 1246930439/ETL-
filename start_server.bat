@echo off
echo Starting server with auto-restart...
:restart
python web_scheduler.py
echo Server stopped at %date% %time%
echo Restarting in 5 seconds...
timeout /t 5 /nobreak > nul
goto restart