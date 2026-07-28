@echo off
title Control Center Installer
echo.
echo  ========================================
echo   Control Center - One-Click Installer
echo  ========================================
echo.

:: Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo  [!] Node.js not found. Installing...
    echo  [*] Downloading Node.js...
    powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.18.0/node-v20.18.0-x64.msi' -OutFile '%TEMP%\node-installer.msi'"
    echo  [*] Installing Node.js...
    msiexec /i "%TEMP%\node-installer.msi" /qn
    del "%TEMP%\node-installer.msi"
    echo  [+] Node.js installed. Please close and reopen this window, then run install.bat again.
    pause
    exit
)

echo  [+] Node.js found:
node --version

:: Install dependencies
echo.
echo  [*] Installing dependencies...
call npm install --production
echo  [+] Dependencies installed.

:: Generate session secret if default
echo.
echo  [*] Checking session secret...
findstr /C:"change_this" .env >nul 2>nul
if %errorlevel% equ 0 (
    echo  [*] Generating new session secret...
    for /f %%i in ('node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"') do set SECRET=%%i
    powershell -Command "(Get-Content .env) -replace 'change_this_to_random_64_chars', '%SECRET%' | Set-Content .env"
    echo  [+] Session secret generated.
) else (
    echo  [+] Session secret already set.
)

:: Run obfuscator
echo.
echo  [*] Obfuscating frontend code...
call node obfuscate.js
echo  [+] Obfuscation complete.

:: Open firewall
echo.
echo  [*] Opening firewall port 3000...
netsh advfirewall firewall add rule name="ControlCenter" dir=in action=allow protocol=TCP localport=3000 >nul 2>nul
echo  [+] Firewall port 3000 open.

:: Install PM2
echo.
echo  [*] Installing PM2 (keeps server running 24/7)...
call npm install -g pm2 >nul 2>nul
echo  [+] PM2 installed.

:: Start with PM2
echo.
echo  [*] Starting server...
call pm2 delete panel >nul 2>nul
call pm2 start server.js --name panel
call pm2 save

echo.
echo  ========================================
echo   INSTALLATION COMPLETE
echo  ========================================
echo.
echo  Server running at: http://localhost:3000
echo  Admin panel: http://localhost:3000/u/login
echo.
echo  Default login:
echo    Username: Check .env (ADMIN_USER)
echo    Password: Check .env (ADMIN_PASS)
echo.
echo  Commands:
echo    pm2 logs panel     - View live logs
echo    pm2 restart panel  - Restart server
echo    pm2 stop panel     - Stop server
echo.
pause
