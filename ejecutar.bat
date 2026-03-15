@echo off
set "PATH=C:\Users\miagu\AppData\Local\Programs\Python\Python313;%PATH%"
echo Python agregado al PATH
echo.
python --version
echo.
echo Ejecutando agente...
echo.
python "%~dp0agente.py"
pause