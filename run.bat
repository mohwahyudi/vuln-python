@echo off
setlocal enabledelayedexpansion

echo Security Vulnerabilities Demo
echo ===========================
echo.
echo This script helps you run the vulnerable and secure applications.
echo.

:menu
echo Choose an option:
echo 1. Run vulnerable application
echo 2. Run secure application
echo 3. Run both applications using Docker Compose
echo 4. Run vulnerability tests against the vulnerable app
echo 5. Run vulnerability tests against the secure app
echo 6. Run all PoC exploits against the vulnerable app
echo 7. Exit
echo.

set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" goto run_vulnerable
if "%choice%"=="2" goto run_secure
if "%choice%"=="3" goto run_docker
if "%choice%"=="4" goto test_vulnerable
if "%choice%"=="5" goto test_secure
if "%choice%"=="6" goto run_poc
if "%choice%"=="7" goto exit

echo Invalid option. Please try again.
echo.
goto menu

:run_vulnerable
echo Starting vulnerable application on http://localhost:5000
echo Press Ctrl+C to stop
python vulnerable_app.py
goto end

:run_secure
echo Starting secure application on http://localhost:5000
echo Press Ctrl+C to stop
python secure_app.py
goto end

:run_docker
echo Starting both applications using Docker Compose
echo Vulnerable app will be available at http://localhost:5000
echo Secure app will be available at http://localhost:5001
echo Press Ctrl+C to stop
docker-compose up --build
goto end

:test_vulnerable
echo Running vulnerability tests against the vulnerable app
python test_vulnerabilities.py http://localhost:5000
goto end

:test_secure
echo Running vulnerability tests against the secure app
python test_vulnerabilities.py http://localhost:5001
goto end

:run_poc
echo Running all PoC exploits against the vulnerable app
python poc/run_all_pocs.py http://localhost:5000
goto end

:exit
echo Exiting.
goto end

:end
endlocal