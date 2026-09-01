// screen_cap.cpp - Stage 1a of Messager screen share: prove capture + display.
//
// Uses the Desktop Duplication API (DXGI) to grab the primary screen and shows
// it (scaled) in a window. No encoding yet - this establishes the D3D11 device
// and capture loop the H.264 encoder will reuse. If it works you see the live
// desktop mirrored in the window (a "hall of mirrors").
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 screen_cap.cpp d3d11.lib dxgi.lib ^
//            user32.lib gdi32.lib /Fe:ScreenCap.exe /link /SUBSYSTEM:WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <atomic>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

static HWND g_hwnd;
static std::atomic<bool> g_run{ true };

static ID3D11Device*        g_dev = nullptr;
static ID3D11DeviceContext* g_ctx = nullptr;
static IDXGIOutputDuplication* g_dupl = nullptr;
static ID3D11Texture2D*     g_staging = nullptr;
static UINT g_texW = 0, g_texH = 0;
static std::vector<BYTE> g_packed;   // tightly packed BGRA for StretchDIBits

static bool createDevice() {
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, &g_dev, &fl, &g_ctx);
    return SUCCEEDED(hr);
}
static bool createDuplication() {
    if (g_dupl) { g_dupl->Release(); g_dupl = nullptr; }
    IDXGIDevice* dxgiDev = nullptr;
    if (FAILED(g_dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev))) return false;
    IDXGIAdapter* adapter = nullptr; dxgiDev->GetAdapter(&adapter); dxgiDev->Release();
    if (!adapter) return false;
    IDXGIOutput* output = nullptr; adapter->EnumOutputs(0, &output); adapter->Release();
    if (!output) return false;
    IDXGIOutput1* output1 = nullptr; output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1); output->Release();
    if (!output1) return false;
    HRESULT hr = output1->DuplicateOutput(g_dev, &g_dupl); output1->Release();
    return SUCCEEDED(hr);
}
static void ensureStaging(UINT w, UINT h) {
    if (g_staging && w == g_texW && h == g_texH) return;
    if (g_staging) { g_staging->Release(); g_staging = nullptr; }
    g_texW = w; g_texH = h; g_packed.resize((size_t)w * h * 4);
    D3D11_TEXTURE2D_DESC d{};
    d.Width = w; d.Height = h; d.MipLevels = 1; d.ArraySize = 1;
    d.Format = DXGI_FORMAT_B8G8R8A8_UNORM; d.SampleDesc.Count = 1;
    d.Usage = D3D11_USAGE_STAGING; d.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    g_dev->CreateTexture2D(&d, nullptr, &g_staging);
}

// Grab one frame into g_packed. Returns true if a new frame was captured.
static bool captureFrame() {
    DXGI_OUTDUPL_FRAME_INFO info{}; IDXGIResource* res = nullptr;
    HRESULT hr = g_dupl->AcquireNextFrame(15, &info, &res);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return false;
    if (hr == DXGI_ERROR_ACCESS_LOST) { createDuplication(); return false; }
    if (FAILED(hr) || !res) return false;
    ID3D11Texture2D* tex = nullptr; res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&tex); res->Release();
    if (!tex) { g_dupl->ReleaseFrame(); return false; }
    D3D11_TEXTURE2D_DESC td{}; tex->GetDesc(&td);
    ensureStaging(td.Width, td.Height);
    g_ctx->CopyResource(g_staging, tex);
    tex->Release();
    D3D11_MAPPED_SUBRESOURCE m{};
    if (SUCCEEDED(g_ctx->Map(g_staging, 0, D3D11_MAP_READ, 0, &m))) {
        const BYTE* src = (const BYTE*)m.pData;
        for (UINT y = 0; y < g_texH; ++y)
            memcpy(&g_packed[(size_t)y * g_texW * 4], src + (size_t)y * m.RowPitch, (size_t)g_texW * 4);
        g_ctx->Unmap(g_staging, 0);
    }
    g_dupl->ReleaseFrame();
    return true;
}
static void present() {
    if (g_texW == 0) return;
    RECT rc; GetClientRect(g_hwnd, &rc);
    HDC dc = GetDC(g_hwnd);
    BITMAPINFO bmi{}; bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = g_texW; bmi.bmiHeader.biHeight = -(LONG)g_texH; // top-down
    bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(dc, HALFTONE);
    StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, g_texW, g_texH,
                  g_packed.data(), &bmi, DIB_RGB_COLORS, SRCCOPY);
    ReleaseDC(g_hwnd, dc);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { g_run = false; PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmd) {
    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst;
    wc.lpszClassName = L"ScreenCap"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, L"ScreenCap", L"Messager - Screen Capture Test",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 560, nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_hwnd, nCmd);

    if (!createDevice() || !createDuplication()) {
        MessageBoxW(g_hwnd, L"Could not start screen capture (Desktop Duplication).", L"ScreenCap", MB_ICONERROR);
        return 1;
    }
    MSG msg;
    while (g_run) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { g_run = false; break; }
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        if (!g_run) break;
        if (captureFrame()) present();
        else Sleep(1);
    }
    if (g_staging) g_staging->Release();
    if (g_dupl) g_dupl->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
    return 0;
}
