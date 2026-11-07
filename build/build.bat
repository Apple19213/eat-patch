@echo off
setlocal
cd /d "%~dp0.."

set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo ERROR: csc.exe not found. Install .NET Framework 4.x first.
    exit /b 1
)
where nasm >nul 2>nul
if errorlevel 1 (
    echo ERROR: nasm not found. Install NASM and add it to PATH.
    exit /b 1
)

if not exist build mkdir build

echo [1/2] assembling stub blob ...
pushd src
nasm -f bin -l stub.lst -o ..\build\stub.bin stub.asm
if errorlevel 1 (
    popd
    echo ERROR: nasm failed
    exit /b 1
)
for %%A in (..\build\stub.bin) do echo       stub.bin = %%~zA bytes

echo [2/2] compiling launcher ...
"%CSC%" -nologo -target:winexe -platform:x86 -optimize+ ^
    -out:..\build\launcher.exe -resource:..\build\stub.bin,stub.bin launch.cs
if errorlevel 1 (
    popd
    echo ERROR: csc failed
    exit /b 1
)
for %%A in (..\build\launcher.exe) do echo       launcher.exe = %%~zA bytes
if exist stub.lst del /q stub.lst
popd

echo.
echo Done. Usage (put build\launcher.exe next to the target program):
echo    launcher.exe                  silent launch
echo    launcher.exe --verbose        keep console for debugging
echo    launcher.exe "D:\app\dir"     explicit target directory
