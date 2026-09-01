// shr.cpp - test harness for the Messager screen-share engine (screen_engine.h).
// Thin CLI over the SAME code the client uses, so it exercises the real engine:
//   shr.exe send <host> <udpPort> <token> [seconds] [quality 0-2]
//   shr.exe recv <host> <udpPort> <token> [seconds] [layer 0-2]
// send: capture -> up to 3 simulcast layers -> UDP. recv: SUBSCRIBE(layer) ->
// decode -> a window. Run one sender and two receivers on different layers to
// see the server forward each viewer only its chosen layer.
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 shr.cpp d3d11.lib dxgi.lib mfplat.lib ^
//   mfuuid.lib wmcodecdspuuid.lib ole32.lib ws2_32.lib user32.lib gdi32.lib /Fe:shr.exe
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include "screen_engine.h"
#include <cstdio>
#include <string>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

int wmain(int argc, wchar_t** argv) {
    if (argc < 5) { printf("usage: shr send|recv <host> <udpPort> <token> [seconds] [quality/layer]\n"); return 1; }
    char host[256], port[16], tok[64];
    WideCharToMultiByte(CP_ACP, 0, argv[2], -1, host, 256, 0, 0);
    WideCharToMultiByte(CP_ACP, 0, argv[3], -1, port, 16, 0, 0);
    WideCharToMultiByte(CP_ACP, 0, argv[4], -1, tok, 64, 0, 0);
    std::wstring mode = argv[1]; int seconds = (argc >= 6) ? _wtoi(argv[5]) : 30; int extra = (argc >= 7) ? _wtoi(argv[6]) : 0;
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    int p = atoi(port);
    if (mode == L"send") {
        printf("sharing (quality %d) for %ds...\n", extra, seconds); fflush(stdout);
        screen::shareStart(host, p, tok, extra);
        Sleep((DWORD)seconds * 1000);
        screen::shareStop();
        printf("share stopped, packets sent=%lld\n", screen::g_dbgSent.load());
    } else {
        printf("viewing layer %d for %ds...\n", extra, seconds); fflush(stdout);
        screen::viewStart(host, p, tok, L"shr viewer (layer " + std::to_wstring(extra) + L")", extra);
        for (int i = 0; i < seconds * 10 && screen::viewing(); ++i) Sleep(100);
        screen::viewStop();
        printf("view stopped: recv=%lld frames=%lld decoded=%lld res=%ux%u\n", screen::g_dbgRecv.load(), screen::g_dbgFrames.load(), screen::g_dbgDecoded.load(), screen::V.W, screen::V.H);
    }
    WSACleanup();
    return 0;
}
