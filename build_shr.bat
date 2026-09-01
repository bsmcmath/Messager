@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
echo Building shr.exe...
cl /nologo /std:c++17 /utf-8 /EHsc /O2 shr.cpp d3d11.lib dxgi.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib ws2_32.lib user32.lib gdi32.lib /Fe:shr.exe
if %errorlevel% neq 0 ( echo SHR BUILD FAILED & exit /b 1 )
rc /nologo /fo res_server.res res_server.rc || ( echo RC FAILED & exit /b 1 )
echo Building Messager.exe...
cl /nologo /std:c++17 /utf-8 /EHsc /O2 server.cpp res_server.res ws2_32.lib bcrypt.lib /Fe:Messager.exe /link /MANIFEST:NO
if %errorlevel% neq 0 ( echo CONSOLE BUILD FAILED & exit /b 1 )
del /q *.obj *.res 2>nul
echo BUILD OK
