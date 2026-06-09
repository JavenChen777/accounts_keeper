@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
)

if not defined VSINSTALL set "VSINSTALL=%ProgramFiles%\Microsoft Visual Studio\2022\Community"
if not exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
  echo Could not find Visual Studio C++ build tools.
  exit /b 1
)

call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
if not exist build-direct mkdir build-direct

rc /nologo /fo build-direct\AccountsKeeper.res src\AccountsKeeper.rc || exit /b 1

cl /nologo /std:c++17 /EHsc ^
  /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
  /Fo:build-direct\ /Fe:build-direct\AccountsKeeper.exe src\main.cpp build-direct\AccountsKeeper.res ^
  /link /SUBSYSTEM:WINDOWS ^
  advapi32.lib comctl32.lib crypt32.lib gdi32.lib ole32.lib shell32.lib shlwapi.lib user32.lib winhttp.lib
