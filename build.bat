@echo off
REM Build all Messager executables using the installed Visual Studio compiler.
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo Could not find vcvars64.bat. Edit build.bat with your Visual Studio path.
  exit /b 1
)
call "%VCVARS%"

echo Compiling resources (icon + version info + manifest)...
rc /nologo /fo res_admin.res  res_admin.rc  || ( echo RC FAILED & exit /b 1 )
rc /nologo /fo res_client.res res_client.rc || ( echo RC FAILED & exit /b 1 )
rc /nologo /fo res_server.res res_server.rc || ( echo RC FAILED & exit /b 1 )

echo Building MessagerAdmin.exe (desktop control panel)...
cl /nologo /std:c++17 /utf-8 /EHsc /O2 admin.cpp res_admin.res ws2_32.lib bcrypt.lib comctl32.lib wininet.lib shell32.lib user32.lib gdi32.lib uxtheme.lib /Fe:MessagerAdmin.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:NO
if %errorlevel% neq 0 ( echo. & echo ADMIN BUILD FAILED & exit /b 1 )

echo Building Messager.exe (headless console version)...
cl /nologo /std:c++17 /utf-8 /EHsc /O2 server.cpp res_server.res ws2_32.lib bcrypt.lib /Fe:Messager.exe /link /MANIFEST:NO
if %errorlevel% neq 0 ( echo. & echo CONSOLE BUILD FAILED & exit /b 1 )

echo Building MessagerClient.exe (desktop client, needs Edge WebView2 Runtime)...
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /MT client.cpp res_client.res /I sdk\include /I sdk\opus\include sdk\lib\WebView2LoaderStatic.lib sdk\opus\lib\opus.lib ws2_32.lib crypt32.lib ole32.lib oleaut32.lib version.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib d3d11.lib dxgi.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib /Fe:MessagerClient.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:NO /NODEFAULTLIB:MSVCRT /IGNORE:4049,4217,4286
if %errorlevel% neq 0 ( echo. & echo CLIENT BUILD FAILED & exit /b 1 )

del /q *.obj *.res 2>nul
echo.
echo BUILD OK -^> MessagerAdmin.exe  Messager.exe  MessagerClient.exe
