@echo off
title ScanApp Installer
color 0f
cls

echo ========================================================
echo   SCANAPP - INSTALADOR AUTOMATICO
echo ========================================================
echo.

:: 1. CHECK PYTHON
echo [1/3] Verificando Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado.
    echo Por favor instale Python 3.10+ y agreguelo al PATH.
    pause
    exit /b
)
echo [OK] Python detectado.
echo.

:: 2. INSTALL DEPS
echo [2/3] Instalando Dependencias Python...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Fallo al instalar librerias.
    echo Puede intentar ejecutar manualmente: python -m pip install -r requirements.txt
    pause
    exit /b
)
echo [OK] Librerias instaladas.
echo.

:: 3. CHECK ZAP
echo [3/3] Verificando ZAP (OWASP Zed Attack Proxy)...

if exist "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" goto ZAP_FOUND
if exist "C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat" goto ZAP_FOUND
if exist "%USERPROFILE%\OWASP ZAP\zap.bat" goto ZAP_FOUND

:ZAP_NOT_FOUND
echo [AVISO] ZAP no encontrado en rutas estandar.
echo.
echo Es necesario tener ZAP instalado para que el escaner funcione.
echo Desea descargar e instalar ZAP automaticamente ahora? (180MB)
echo.

set /p "choice=Escriba S para SI o N para NO: "
if /i "%choice%" neq "S" goto SKIP_ZAP

echo.
echo Descargando instalador de ZAP... Espere un momento...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/zaproxy/zaproxy/releases/download/v2.16.0/ZAP_2_16_0_windows.exe' -OutFile 'zap_installer.exe'"

if not exist zap_installer.exe (
    echo [ERROR] No se pudo descargar el archivo.
    echo Intente descargarlo manualmente de: https://www.zaproxy.org/download/
    pause
    goto END
)

echo.
echo [OK] Descarga completada.
echo Lanzando el instalador... Por favor siga los pasos (Next, Next...)
start /wait zap_installer.exe

echo Limpiando archivos temporales...
del zap_installer.exe
echo [OK] Instalacion finalizada.
goto END

:ZAP_FOUND
echo [OK] ZAP encontrado correctamente.

:SKIP_ZAP
echo.

:END
echo.
echo ========================================================
echo   INSTALACION COMPLETADA
echo ========================================================
echo.
echo Ejecute "run.bat" o "main.py" para iniciar la aplicacion.
echo.
pause
