// screen_h264.cpp - Stage 1b(ii): full local codec loopback.
// Capture screen -> BGRA->NV12 -> H.264 encode -> H.264 decode -> NV12->BGRA ->
// display. If the window shows the desktop, the whole codec round-trip works.
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 screen_h264.cpp d3d11.lib dxgi.lib ^
//   mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib user32.lib gdi32.lib ^
//   /Fe:ScreenH264.exe /link /SUBSYSTEM:WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <codecapi.h>
#include <wmcodecdsp.h>
#include <atomic>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

static HWND g_hwnd; static std::atomic<bool> g_run{ true };
static ID3D11Device* g_dev = nullptr; static ID3D11DeviceContext* g_ctx = nullptr;
static IDXGIOutputDuplication* g_dupl = nullptr; static ID3D11Texture2D* g_staging = nullptr;
static UINT W = 0, H = 0; static std::vector<BYTE> g_bgra, g_out; // g_out = display BGRA
static IMFTransform* g_enc = nullptr; static IMFTransform* g_dec = nullptr;

static bool initCapture() {
    D3D_FEATURE_LEVEL fl;
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, &g_dev, &fl, &g_ctx))) return false;
    IDXGIDevice* dd = nullptr; g_dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dd);
    IDXGIAdapter* ad = nullptr; dd->GetAdapter(&ad); dd->Release();
    IDXGIOutput* o = nullptr; ad->EnumOutputs(0, &o); ad->Release();
    IDXGIOutput1* o1 = nullptr; o->QueryInterface(__uuidof(IDXGIOutput1), (void**)&o1); o->Release();
    HRESULT hr = o1->DuplicateOutput(g_dev, &g_dupl); o1->Release(); return SUCCEEDED(hr);
}
static bool capture() {
    DXGI_OUTDUPL_FRAME_INFO info{}; IDXGIResource* res = nullptr;
    HRESULT hr = g_dupl->AcquireNextFrame(30, &info, &res);
    if (FAILED(hr) || !res) return false;
    ID3D11Texture2D* tex = nullptr; res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&tex); res->Release();
    D3D11_TEXTURE2D_DESC td{}; tex->GetDesc(&td);
    if (!g_staging) { W = td.Width; H = td.Height; g_bgra.resize((size_t)W * H * 4); g_out.resize((size_t)W * H * 4);
        D3D11_TEXTURE2D_DESC d = td; d.Usage = D3D11_USAGE_STAGING; d.CPUAccessFlags = D3D11_CPU_ACCESS_READ; d.BindFlags = 0; d.MiscFlags = 0; g_dev->CreateTexture2D(&d, nullptr, &g_staging); }
    g_ctx->CopyResource(g_staging, tex); tex->Release();
    D3D11_MAPPED_SUBRESOURCE m{};
    if (SUCCEEDED(g_ctx->Map(g_staging, 0, D3D11_MAP_READ, 0, &m))) {
        for (UINT y = 0; y < H; ++y) memcpy(&g_bgra[(size_t)y * W * 4], (BYTE*)m.pData + (size_t)y * m.RowPitch, (size_t)W * 4);
        g_ctx->Unmap(g_staging, 0);
    }
    g_dupl->ReleaseFrame(); return true;
}
static void bgraToNV12(const BYTE* b, BYTE* nv) {
    BYTE* Y = nv; BYTE* UV = nv + (size_t)W * H;
    for (UINT y = 0; y < H; ++y) for (UINT x = 0; x < W; ++x) { const BYTE* p = b + ((size_t)y * W + x) * 4;
        int B = p[0], G = p[1], R = p[2]; Y[(size_t)y * W + x] = (BYTE)((66 * R + 129 * G + 25 * B + 128 >> 8) + 16); }
    for (UINT y = 0; y < H; y += 2) for (UINT x = 0; x < W; x += 2) { const BYTE* p = b + ((size_t)y * W + x) * 4;
        int B = p[0], G = p[1], R = p[2]; BYTE* d = UV + (size_t)(y / 2) * W + x;
        d[0] = (BYTE)((-38 * R - 74 * G + 112 * B + 128 >> 8) + 128); d[1] = (BYTE)((112 * R - 94 * G - 18 * B + 128 >> 8) + 128); }
}
static void nv12ToBgra(const BYTE* nv, BYTE* bgra) {
    const BYTE* Y = nv; const BYTE* UV = nv + (size_t)W * H; auto cl = [](int a) { return a < 0 ? 0 : (a > 255 ? 255 : a); };
    for (UINT y = 0; y < H; ++y) for (UINT x = 0; x < W; ++x) {
        int yy = Y[(size_t)y * W + x] - 16; size_t uv = (size_t)(y / 2) * W + (x & ~1u);
        int u = UV[uv] - 128, v = UV[uv + 1] - 128, c = 298 * yy;
        BYTE* d = bgra + ((size_t)y * W + x) * 4;
        d[0] = (BYTE)cl(c + 516 * u + 128 >> 8); d[1] = (BYTE)cl(c - 100 * u - 208 * v + 128 >> 8); d[2] = (BYTE)cl(c + 409 * v + 128 >> 8); d[3] = 255;
    }
}
static IMFSample* makeSample(const BYTE* data, size_t len, LONGLONG t, LONGLONG dur) {
    IMFSample* s = nullptr; MFCreateSample(&s); IMFMediaBuffer* b = nullptr; MFCreateMemoryBuffer((DWORD)len, &b);
    BYTE* p; DWORD mx; b->Lock(&p, &mx, nullptr); memcpy(p, data, len); b->Unlock(); b->SetCurrentLength((DWORD)len);
    s->AddBuffer(b); b->Release(); s->SetSampleTime(t); s->SetSampleDuration(dur); return s;
}
static bool setDecOutNV12() {
    for (DWORD i = 0;; ++i) { IMFMediaType* t = nullptr; if (FAILED(g_dec->GetOutputAvailableType(0, i, &t))) break;
        GUID sub; t->GetGUID(MF_MT_SUBTYPE, &sub); if (sub == MFVideoFormat_NV12) { HRESULT hr = g_dec->SetOutputType(0, t, 0); t->Release(); return SUCCEEDED(hr); } t->Release(); }
    return false;
}
static bool initCodec(UINT fps, UINT br) {
    if (FAILED(CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&g_enc)))) return false;
    IMFMediaType* ot; MFCreateMediaType(&ot); ot->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); ot->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    ot->SetUINT32(MF_MT_AVG_BITRATE, br); MFSetAttributeSize(ot, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(ot, MF_MT_FRAME_RATE, fps, 1);
    ot->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); MFSetAttributeRatio(ot, MF_MT_PIXEL_ASPECT_RATIO, 1, 1); ot->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
    if (FAILED(g_enc->SetOutputType(0, ot, 0))) return false;
    IMFMediaType* it; MFCreateMediaType(&it); it->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); it->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
    MFSetAttributeSize(it, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(it, MF_MT_FRAME_RATE, fps, 1); it->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); MFSetAttributeRatio(it, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    if (FAILED(g_enc->SetInputType(0, it, 0))) return false;
    g_enc->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0); g_enc->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);

    if (FAILED(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&g_dec)))) return false;
    IMFMediaType* dit; MFCreateMediaType(&dit); dit->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); dit->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    MFSetAttributeSize(dit, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(dit, MF_MT_FRAME_RATE, fps, 1); dit->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    if (FAILED(g_dec->SetInputType(0, dit, 0))) return false;
    setDecOutNV12();
    g_dec->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0); g_dec->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    return true;
}
static void present() {
    RECT rc; GetClientRect(g_hwnd, &rc); HDC dc = GetDC(g_hwnd);
    BITMAPINFO bmi{}; bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); bmi.bmiHeader.biWidth = W; bmi.bmiHeader.biHeight = -(LONG)H;
    bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(dc, HALFTONE); StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, W, H, g_out.data(), &bmi, DIB_RGB_COLORS, SRCCOPY); ReleaseDC(g_hwnd, dc);
}
// decode one H.264 sample -> display
static void decodeAndShow(IMFSample* h264) {
    g_dec->ProcessInput(0, h264, 0);
    while (true) {
        MFT_OUTPUT_STREAM_INFO si{}; g_dec->GetOutputStreamInfo(0, &si);
        MFT_OUTPUT_DATA_BUFFER ob{}; IMFSample* out = nullptr;
        bool alloc = !(si.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES));
        if (alloc) { MFCreateSample(&out); IMFMediaBuffer* mb; MFCreateMemoryBuffer(si.cbSize ? si.cbSize : (DWORD)(W * H * 3 / 2), &mb); out->AddBuffer(mb); mb->Release(); ob.pSample = out; }
        DWORD st = 0; HRESULT hr = g_dec->ProcessOutput(0, 1, &ob, &st);
        if (hr == MF_E_TRANSFORM_STREAM_CHANGE) { if (ob.pSample) ob.pSample->Release(); setDecOutNV12(); continue; }
        if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) { if (ob.pSample) ob.pSample->Release(); break; }
        if (FAILED(hr)) { if (ob.pSample) ob.pSample->Release(); break; }
        IMFSample* r = ob.pSample; IMFMediaBuffer* cb = nullptr; r->ConvertToContiguousBuffer(&cb);
        BYTE* p; DWORD ln; cb->Lock(&p, nullptr, &ln); if (ln >= (DWORD)(W * H * 3 / 2)) nv12ToBgra(p, g_out.data()); cb->Unlock(); cb->Release();
        r->Release(); present();
    }
}
static void encodeFrame(const BYTE* nv12, LONGLONG t, LONGLONG dur) {
    IMFSample* in = makeSample(nv12, (size_t)W * H * 3 / 2, t, dur); g_enc->ProcessInput(0, in, 0); in->Release();
    while (true) {
        MFT_OUTPUT_STREAM_INFO si{}; g_enc->GetOutputStreamInfo(0, &si);
        MFT_OUTPUT_DATA_BUFFER ob{}; IMFSample* out = nullptr;
        bool alloc = !(si.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES);
        if (alloc) { MFCreateSample(&out); IMFMediaBuffer* mb; MFCreateMemoryBuffer(si.cbSize ? si.cbSize : (DWORD)(W * H), &mb); out->AddBuffer(mb); mb->Release(); ob.pSample = out; }
        DWORD st = 0; HRESULT hr = g_enc->ProcessOutput(0, 1, &ob, &st);
        if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) { if (out) out->Release(); break; }
        if (FAILED(hr)) { if (out) out->Release(); break; }
        decodeAndShow(ob.pSample);   // straight into the decoder (loopback)
        ob.pSample->Release();
    }
}
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) { if (m == WM_DESTROY) { g_run = false; PostQuitMessage(0); return 0; } return DefWindowProcW(h, m, w, l); }
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmd) {
    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"ScreenH264"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, L"ScreenH264", L"Messager - Screen H.264 Loopback", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 560, nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_hwnd, nCmd);
    MFStartup(MF_VERSION);
    if (!initCapture()) { MessageBoxW(g_hwnd, L"Capture init failed", L"ScreenH264", MB_ICONERROR); return 1; }
    for (int i = 0; i < 50 && W == 0; ++i) capture();
    if (W == 0 || !initCodec(30, 4000000)) { MessageBoxW(g_hwnd, L"Codec init failed", L"ScreenH264", MB_ICONERROR); return 1; }
    MSG msg; LONGLONG t = 0; const LONGLONG dur = 10000000LL / 30; std::vector<BYTE> nv((size_t)W * H * 3 / 2);
    while (g_run) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { if (msg.message == WM_QUIT) { g_run = false; break; } TranslateMessage(&msg); DispatchMessageW(&msg); }
        if (!g_run) break;
        if (capture()) { bgraToNV12(g_bgra.data(), nv.data()); encodeFrame(nv.data(), t, dur); t += dur; }
        else Sleep(1);
    }
    if (g_enc) g_enc->Release(); if (g_dec) g_dec->Release(); if (g_staging) g_staging->Release(); if (g_dupl) g_dupl->Release(); if (g_ctx) g_ctx->Release(); if (g_dev) g_dev->Release(); MFShutdown();
    return 0;
}
