@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /std:c++17 /utf-8 /EHsc /O2 screen_encode.cpp d3d11.lib dxgi.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib /Fe:ScreenEncode.exe >nul
