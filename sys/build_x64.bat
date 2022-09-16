@echo off
set WDKPATH=C:\WinDDK\7600.16385.1
set DDK_BUILD_ARGS=fre x64 WNET

PUSHD %WDKPATH%\bin
call SETENV.bat %WDKPATH%\ %DDK_BUILD_ARGS% no_oacr
if ERRORLEVEL 1 exit /b 1
POPD

PUSHD ..\aesni
echo ==================================================================
echo Builing AESNI
echo ==================================================================
@if not exist drvlib\amd64\aesni.lib set BUILD_AESNI_X64=X
@if not exist applib\amd64\aesni.lib set BUILD_AESNI_X64=X
@if %BUILD_AESNI_X64%.==X. BUILD  /ceZ
if ERRORLEVEL 1 exit /b 1
POPD

PUSHD ..\rsa
echo ==================================================================
echo Builing RSA
echo ==================================================================
BUILD /ceZ
if ERRORLEVEL 1 exit /b 1
POPD

echo ==================================================================
echo Builing Layered File System Driver
echo ==================================================================
BUILD  /ceZ
if ERRORLEVEL 1 exit /b 1

echo ==================================================================
echo Done!
echo ==================================================================
exit /b 0
