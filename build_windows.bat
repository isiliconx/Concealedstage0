# language: Batch, file: build_windows.bat, target: Windows 10/11 x64, requires: MSVC Build Tools
@echo off
REM Build conceal.exe -- run from a "x64 Native Tools Command Prompt for VS"
REM or with vcvarsall.bat sourced. Produces a console-subsystem PE32+.

setlocal

where cl >nul 2>&1
if errorlevel 1 (
    echo [x] cl.exe not on PATH. Source vcvarsall.bat first:
    echo     call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
    exit /b 1
)

echo [*] compiling conceal.cpp
cl /nologo /std:c++20 /EHsc /W4 /O2 /GS- /guard:cf ^
   conceal.cpp ^
   /Fe:conceal.exe ^
   /link /SUBSYSTEM:CONSOLE /ENTRY:wMain ^
   advapi32.lib user32.lib

if errorlevel 1 (
    echo [x] build failed
    exit /b 1
)

echo [*] built conceal.exe
where dumpbin >nul 2>&1 && dumpbin /headers conceal.exe | findstr /C:"machine" /C:"subsystem"
echo [*] done. Sign it before it goes anywhere: an unsigned PE is an IOC by itself.
endlocal
