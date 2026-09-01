// screen_engine.h - native screen-share engine embedded in MessagerClient.
// Two roles, each on its own thread + UDP socket to the server relay:
//   share: Desktop Duplication -> N simulcast layers (downscale/NV12/H.264) ->
//          fragment (tagged with layer id) -> UDP. The sharer's quality setting
//          picks how many layers to send (1=low, 2=+medium, 3=+high).
//   view : SUBSCRIBE(layer) -> UDP (server forwards only that layer) -> reassemble
//          -> H.264 decode -> NV12->BGRA -> a native window. The viewer can switch
//          layer live (re-subscribe + resync on the next keyframe).
// Controlled by shareStart/shareStop and viewStart/viewStop/viewSetLayer.
// Assumes winsock2, windows.h and WSAStartup are set up by client.cpp.
#pragma once
#include <ws2tcpip.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <codecapi.h>
#include <wmcodecdsp.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace screen {

static const unsigned char V_HELLO = 0x01, V_WELCOME = 0x02, V_PING = 0x04, V_VIDEO = 0x05, V_SUB = 0x06;
static const int VHDR = 13;                 // type(1)+sid(2)+frameId(4)+fragIdx(2)+fragCount(2)+key(1)+layer(1)
static const DWORD FRAGSZ = 1200;

struct LayerDef { int w, fps, br; };
static const LayerDef LAYERS[3] = { {640, 10, 400000}, {1280, 15, 1500000}, {1920, 30, 4000000} };

inline std::atomic<long long> g_dbgSent{ 0 }, g_dbgRecv{ 0 }, g_dbgFrames{ 0 }, g_dbgDecoded{ 0 };   // lightweight counters for the shr test harness

// ---------- shared helpers ----------
inline bool joinRoom(SOCKET& sock, const std::string& host, int port, const std::string& token, uint16_t& myId, std::atomic<bool>& run) {
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; addrinfo* res = nullptr;
    char ps[16]; sprintf_s(ps, "%d", port);
    if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) return false;
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int buf = 8 * 1024 * 1024; setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf, sizeof(buf)); setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&buf, sizeof(buf));
    connect(sock, res->ai_addr, (int)res->ai_addrlen); freeaddrinfo(res);
    DWORD tmo = 100; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
    char hello[17]; hello[0] = V_HELLO; memcpy(hello + 1, token.data(), 16);
    for (int t = 0; t < 20 && myId == 0 && run; ++t) { send(sock, hello, 17, 0); char r[8]; int n = recv(sock, r, sizeof(r), 0); if (n >= 3 && (unsigned char)r[0] == V_WELCOME) memcpy(&myId, r + 1, 2); }
    return myId != 0;
}
inline IMFSample* makeSample(const BYTE* d, size_t len, LONGLONG t, LONGLONG dur) {
    IMFSample* s = nullptr; MFCreateSample(&s); IMFMediaBuffer* b; MFCreateMemoryBuffer((DWORD)len, &b); BYTE* p; DWORD mx; b->Lock(&p, &mx, nullptr); memcpy(p, d, len); b->Unlock(); b->SetCurrentLength((DWORD)len); s->AddBuffer(b); b->Release(); s->SetSampleTime(t); s->SetSampleDuration(dur); return s;
}
inline void bgraToNV12(const BYTE* b, BYTE* nv, UINT W, UINT H) {
    BYTE* Y = nv; BYTE* UV = nv + (size_t)W * H;
    for (UINT y = 0; y < H; ++y) for (UINT x = 0; x < W; ++x) { const BYTE* p = b + ((size_t)y * W + x) * 4; int B = p[0], G = p[1], R = p[2]; Y[(size_t)y * W + x] = (BYTE)((66 * R + 129 * G + 25 * B + 128 >> 8) + 16); }
    for (UINT y = 0; y < H; y += 2) for (UINT x = 0; x < W; x += 2) { const BYTE* p = b + ((size_t)y * W + x) * 4; int B = p[0], G = p[1], R = p[2]; BYTE* d = UV + (size_t)(y / 2) * W + x; d[0] = (BYTE)((-38 * R - 74 * G + 112 * B + 128 >> 8) + 128); d[1] = (BYTE)((112 * R - 94 * G - 18 * B + 128 >> 8) + 128); }
}
inline void nv12ToBgra(const BYTE* nv, BYTE* bgra, UINT w, UINT h) {
    const BYTE* Y = nv; const BYTE* UV = nv + (size_t)w * h; auto cl = [](int a) { return a < 0 ? 0 : (a > 255 ? 255 : a); };
    for (UINT y = 0; y < h; ++y) for (UINT x = 0; x < w; ++x) { int yy = Y[(size_t)y * w + x] - 16; size_t uv = (size_t)(y / 2) * w + (x & ~1u); int u = UV[uv] - 128, v = UV[uv + 1] - 128, c = 298 * yy; BYTE* d = bgra + ((size_t)y * w + x) * 4; d[0] = (BYTE)cl(c + 516 * u + 128 >> 8); d[1] = (BYTE)cl(c - 100 * u - 208 * v + 128 >> 8); d[2] = (BYTE)cl(c + 409 * v + 128 >> 8); d[3] = 255; }
}
inline void downscaleTo(const BYTE* src, UINT sw, UINT sh, BYTE* dst, UINT dw, UINT dh) {
    for (UINT y = 0; y < dh; ++y) { UINT sy = (UINT)((unsigned long long)y * sh / dh); const BYTE* s = &src[(size_t)sy * sw * 4]; BYTE* d = &dst[(size_t)y * dw * 4];
        for (UINT x = 0; x < dw; ++x) { UINT sx = (UINT)((unsigned long long)x * sw / dw); memcpy(d + (size_t)x * 4, s + (size_t)sx * 4, 4); } }
}
inline IMFTransform* makeEncoder(UINT W, UINT H, int fps, int br, std::vector<BYTE>& seq) {
    IMFTransform* enc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&enc)))) return nullptr;
    IMFMediaType* ot; MFCreateMediaType(&ot); ot->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); ot->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264); ot->SetUINT32(MF_MT_AVG_BITRATE, br); MFSetAttributeSize(ot, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(ot, MF_MT_FRAME_RATE, fps, 1); ot->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); MFSetAttributeRatio(ot, MF_MT_PIXEL_ASPECT_RATIO, 1, 1); ot->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
    if (FAILED(enc->SetOutputType(0, ot, 0))) { ot->Release(); enc->Release(); return nullptr; } ot->Release();
    IMFMediaType* it; MFCreateMediaType(&it); it->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); it->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12); MFSetAttributeSize(it, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(it, MF_MT_FRAME_RATE, fps, 1); it->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); MFSetAttributeRatio(it, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    if (FAILED(enc->SetInputType(0, it, 0))) { it->Release(); enc->Release(); return nullptr; } it->Release();
    IMFMediaType* cur = nullptr; if (SUCCEEDED(enc->GetOutputCurrentType(0, &cur)) && cur) { UINT32 sz = 0; if (SUCCEEDED(cur->GetBlobSize(MF_MT_MPEG_SEQUENCE_HEADER, &sz)) && sz) { seq.resize(sz); cur->GetBlob(MF_MT_MPEG_SEQUENCE_HEADER, seq.data(), sz, &sz); } cur->Release(); }
    IMFAttributes* ca = nullptr; if (SUCCEEDED(enc->QueryInterface(IID_PPV_ARGS(&ca)))) { ca->SetUINT32(CODECAPI_AVEncMPVGOPSize, fps); ca->Release(); }
    enc->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0); enc->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0); return enc;
}

// ---------- share ----------
inline std::atomic<bool> g_sRun{ false };
inline std::thread g_sThread;

struct EncLayer {
    int idx; UINT W, H; int fps; DWORD frameMs, lastEnc; LONGLONG t, dur; uint32_t fid;
    IMFTransform* enc; std::vector<BYTE> seq, scaled, nv;
};

// small always-on-top self-view so the sharer can see what they're sending.
// Owned by the share thread (one sharer at a time); paints the latest captured frame.
inline HWND g_prevHwnd = nullptr;
inline const std::vector<BYTE>* g_prevBgra = nullptr;
inline UINT g_prevW = 0, g_prevH = 0;
inline void prevDraw(HDC dc) {
    if (!g_prevBgra || !g_prevW || g_prevBgra->empty()) return; RECT rc; GetClientRect(g_prevHwnd, &rc);
    BITMAPINFO bmi{}; bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); bmi.bmiHeader.biWidth = g_prevW; bmi.bmiHeader.biHeight = -(LONG)g_prevH; bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(dc, HALFTONE); StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, g_prevW, g_prevH, g_prevBgra->data(), &bmi, DIB_RGB_COLORS, SRCCOPY);
}
inline LRESULT CALLBACK PrevWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); prevDraw(dc); EndPaint(h, &ps); return 0; }
    if (m == WM_CLOSE) return 0;                                   // sharing is controlled by the web UI, not this window
    if (m == WM_DESTROY) { g_prevHwnd = nullptr; return 0; }
    return DefWindowProcW(h, m, w, l);
}

inline void shareThread(std::string host, int port, std::string token, int quality) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED); MFStartup(MF_VERSION);
    SOCKET sock = INVALID_SOCKET; uint16_t myId = 0;
    if (!joinRoom(sock, host, port, token, myId, g_sRun)) { if (sock != INVALID_SOCKET) closesocket(sock); MFShutdown(); CoUninitialize(); return; }
    ID3D11Device* dev = nullptr; ID3D11DeviceContext* ctx = nullptr; IDXGIOutputDuplication* dupl = nullptr; ID3D11Texture2D* staging = nullptr;
    D3D_FEATURE_LEVEL fl;
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx))) { closesocket(sock); MFShutdown(); CoUninitialize(); return; }
    { IDXGIDevice* dd = nullptr; dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dd); IDXGIAdapter* ad = nullptr; dd->GetAdapter(&ad); dd->Release();
      IDXGIOutput* chosen = nullptr; DXGI_OUTPUT_DESC cd{};      // prefer the primary monitor (desktop origin 0,0)
      for (UINT i = 0;; ++i) { IDXGIOutput* o = nullptr; if (ad->EnumOutputs(i, &o) != S_OK) break; DXGI_OUTPUT_DESC d{}; o->GetDesc(&d);
          if (!chosen) { chosen = o; cd = d; }
          else if (d.DesktopCoordinates.left == 0 && d.DesktopCoordinates.top == 0) { chosen->Release(); chosen = o; cd = d; }
          else o->Release(); }
      ad->Release();
      if (!chosen) { dev->Release(); ctx->Release(); closesocket(sock); MFShutdown(); CoUninitialize(); return; }
      IDXGIOutput1* o1 = nullptr; chosen->QueryInterface(__uuidof(IDXGIOutput1), (void**)&o1); chosen->Release();
      if (FAILED(o1->DuplicateOutput(dev, &dupl))) { o1->Release(); dev->Release(); ctx->Release(); closesocket(sock); MFShutdown(); CoUninitialize(); return; } o1->Release(); }
    DXGI_OUTDUPL_DESC od{}; dupl->GetDesc(&od);   // dimensions without waiting for a frame
    UINT capW = od.ModeDesc.Width, capH = od.ModeDesc.Height;
    std::vector<BYTE> bgra((size_t)capW * capH * 4, 0);   // starts black until the first frame arrives
    auto capture = [&]() -> bool {   // pull one changed frame if available; false on timeout (screen idle)
        DXGI_OUTDUPL_FRAME_INFO info{}; IDXGIResource* res = nullptr; HRESULT hr = dupl->AcquireNextFrame(15, &info, &res);
        if (hr == DXGI_ERROR_WAIT_TIMEOUT || FAILED(hr) || !res) { if (res) res->Release(); return false; }
        ID3D11Texture2D* tex = nullptr; res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&tex); res->Release(); if (!tex) { dupl->ReleaseFrame(); return false; }
        if (!staging) { D3D11_TEXTURE2D_DESC td{}; tex->GetDesc(&td); td.Usage = D3D11_USAGE_STAGING; td.CPUAccessFlags = D3D11_CPU_ACCESS_READ; td.BindFlags = 0; td.MiscFlags = 0; dev->CreateTexture2D(&td, nullptr, &staging); }   // match the captured format exactly
        ctx->CopyResource(staging, tex); tex->Release();
        D3D11_MAPPED_SUBRESOURCE m{}; if (SUCCEEDED(ctx->Map(staging, 0, D3D11_MAP_READ, 0, &m))) { for (UINT y = 0; y < capH; ++y) memcpy(&bgra[(size_t)y * capW * 4], (BYTE*)m.pData + (size_t)y * m.RowPitch, (size_t)capW * 4); ctx->Unmap(staging, 0); }
        dupl->ReleaseFrame(); return true;
    };
    int nLayers = quality <= 0 ? 1 : (quality == 1 ? 2 : 3);
    std::vector<EncLayer> layers;
    for (int i = 0; i < nLayers; ++i) {
        EncLayer L{}; L.idx = i; L.fps = LAYERS[i].fps;
        UINT w = capW; if (w > (UINT)LAYERS[i].w) w = LAYERS[i].w; UINT h = (UINT)((unsigned long long)capH * w / capW); w &= ~1u; h &= ~1u;
        L.W = w; L.H = h; L.frameMs = 1000 / L.fps; L.lastEnc = 0; L.t = 0; L.dur = 10000000LL / L.fps; L.fid = 1;
        L.scaled.resize((size_t)w * h * 4); L.nv.resize((size_t)w * h * 3 / 2);
        L.enc = makeEncoder(w, h, LAYERS[i].fps, LAYERS[i].br, L.seq);
        if (L.enc) layers.push_back(std::move(L));
    }
    if (layers.empty()) { if (staging) staging->Release(); dupl->Release(); dev->Release(); ctx->Release(); closesocket(sock); MFShutdown(); CoUninitialize(); return; }
    auto sendFrame = [&](int layerIdx, const BYTE* data, DWORD len, bool key, uint32_t& fid) {
        uint16_t count = (uint16_t)((len + FRAGSZ - 1) / FRAGSZ); if (!count) count = 1;
        for (uint16_t i = 0; i < count; ++i) { DWORD off = (DWORD)i * FRAGSZ; DWORD sz = len - off; if (sz > FRAGSZ) sz = FRAGSZ;
            unsigned char pkt[VHDR + FRAGSZ]; pkt[0] = V_VIDEO; memcpy(pkt + 1, &myId, 2); memcpy(pkt + 3, &fid, 4); memcpy(pkt + 7, &i, 2); memcpy(pkt + 9, &count, 2); pkt[11] = key ? 1 : 0; pkt[12] = (unsigned char)layerIdx;
            memcpy(pkt + VHDR, data + off, sz); send(sock, (char*)pkt, VHDR + sz, 0); g_dbgSent++; }
        fid++;
    };
    auto encodeSend = [&](EncLayer& L) {
        IMFSample* in = makeSample(L.nv.data(), L.nv.size(), L.t, L.dur); L.enc->ProcessInput(0, in, 0); in->Release();
        while (true) { MFT_OUTPUT_STREAM_INFO si{}; L.enc->GetOutputStreamInfo(0, &si); MFT_OUTPUT_DATA_BUFFER ob{}; IMFSample* out = nullptr;
            if (!(si.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) { MFCreateSample(&out); IMFMediaBuffer* mb; MFCreateMemoryBuffer(si.cbSize ? si.cbSize : (DWORD)(L.W * L.H * 2), &mb); out->AddBuffer(mb); mb->Release(); ob.pSample = out; }
            DWORD st = 0; HRESULT hr = L.enc->ProcessOutput(0, 1, &ob, &st); if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr)) { if (out) out->Release(); break; }
            IMFSample* r = ob.pSample; UINT32 clean = 0; r->GetUINT32(MFSampleExtension_CleanPoint, &clean); IMFMediaBuffer* cb; r->ConvertToContiguousBuffer(&cb); BYTE* p; DWORD ln; cb->Lock(&p, nullptr, &ln);
            if (clean && !L.seq.empty()) { std::vector<BYTE> b; b.reserve(L.seq.size() + ln); b.insert(b.end(), L.seq.begin(), L.seq.end()); b.insert(b.end(), p, p + ln); sendFrame(L.idx, b.data(), (DWORD)b.size(), true, L.fid); }
            else sendFrame(L.idx, p, ln, clean != 0, L.fid);
            cb->Unlock(); cb->Release(); r->Release(); }
    };
    { static bool pcls = false; if (!pcls) { WNDCLASSW wc{}; wc.lpfnWndProc = PrevWndProc; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"MessagerSharePreview"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH); RegisterClassW(&wc); pcls = true; }
      int pw = 340, ph = (int)((long long)capH * pw / (capW ? capW : 1)); if (ph < 100) ph = 191;
      int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
      g_prevBgra = &bgra; g_prevW = capW; g_prevH = capH;
      g_prevHwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"MessagerSharePreview", L"You're sharing your screen", WS_OVERLAPPEDWINDOW, sx - pw - 40, sy - ph - 90, pw, ph, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
      if (g_prevHwnd) ShowWindow(g_prevHwnd, SW_SHOWNOACTIVATE); }
    DWORD lastPing = GetTickCount(), lastPrev = 0;
    while (g_sRun) {
        DWORD now = GetTickCount();
        MSG msg; while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }   // keep the self-view responsive
        if (!g_sRun) break;
        capture();   // refresh bgra with the latest frame if one is available (else keep the last)
        for (auto& L : layers) if (now - L.lastEnc >= L.frameMs) {   // encode at the layer's fps regardless of motion
            downscaleTo(bgra.data(), capW, capH, L.scaled.data(), L.W, L.H); bgraToNV12(L.scaled.data(), L.nv.data(), L.W, L.H); encodeSend(L); L.t += L.dur; L.lastEnc = now; }
        if (g_prevHwnd && now - lastPrev >= 100) { HDC dc = GetDC(g_prevHwnd); prevDraw(dc); ReleaseDC(g_prevHwnd, dc); lastPrev = now; }   // ~10 fps self-view
        if (now - lastPing > 2000) { unsigned char p[3]; p[0] = V_PING; memcpy(p + 1, &myId, 2); send(sock, (char*)p, 3, 0); lastPing = now; }
        Sleep(1);
    }
    g_prevBgra = nullptr; g_prevW = g_prevH = 0; if (g_prevHwnd) { DestroyWindow(g_prevHwnd); g_prevHwnd = nullptr; }
    for (auto& L : layers) if (L.enc) L.enc->Release();
    if (staging) staging->Release(); dupl->Release(); dev->Release(); ctx->Release(); closesocket(sock); MFShutdown(); CoUninitialize();
}
inline void shareStop() { g_sRun = false; if (g_sThread.joinable()) g_sThread.join(); }
inline void shareStart(const std::string& host, int port, const std::string& token, int quality) { shareStop(); if (token.size() != 16) return; g_sRun = true; g_sThread = std::thread(shareThread, host, port, token, quality); }
inline bool sharing() { return g_sRun; }

// ---------- view ----------
struct ViewState {
    std::atomic<bool> run{ false }; std::thread thread; SOCKET sock = INVALID_SOCKET; uint16_t myId = 0;
    IMFTransform* dec = nullptr; HWND hwnd = nullptr; UINT W = 0, H = 0; std::vector<BYTE> out;
    bool started = false; uint32_t lastDone = 0; DWORD lastPkt = 0; std::wstring title;
    std::atomic<int> layer{ 0 }; std::atomic<bool> layerChanged{ false };
};
inline ViewState V;

inline bool setDecOutNV12() {
    for (DWORD i = 0;; ++i) { IMFMediaType* t = nullptr; if (FAILED(V.dec->GetOutputAvailableType(0, i, &t))) break; GUID sub; t->GetGUID(MF_MT_SUBTYPE, &sub); if (sub == MFVideoFormat_NV12) { UINT32 w = 0, h = 0; MFGetAttributeSize(t, MF_MT_FRAME_SIZE, &w, &h); if (w) { V.W = w; V.H = h; V.out.assign((size_t)V.W * V.H * 4, 0); } HRESULT hr = V.dec->SetOutputType(0, t, 0); t->Release(); return SUCCEEDED(hr); } t->Release(); }
    return false;
}
inline void vpresent(HDC dc) {
    if (V.W == 0 || V.out.empty()) return; RECT rc; GetClientRect(V.hwnd, &rc);
    BITMAPINFO bmi{}; bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); bmi.bmiHeader.biWidth = V.W; bmi.bmiHeader.biHeight = -(LONG)V.H; bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    SetStretchBltMode(dc, HALFTONE); StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, V.W, V.H, V.out.data(), &bmi, DIB_RGB_COLORS, SRCCOPY);
}
inline void vdecode(const BYTE* data, size_t len) {
    IMFSample* in = makeSample(data, len, 0, 0); V.dec->ProcessInput(0, in, 0); in->Release();
    while (true) { MFT_OUTPUT_STREAM_INFO si{}; V.dec->GetOutputStreamInfo(0, &si); MFT_OUTPUT_DATA_BUFFER ob{}; IMFSample* out = nullptr;
        bool alloc = !(si.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES));
        if (alloc) { MFCreateSample(&out); IMFMediaBuffer* mb; MFCreateMemoryBuffer(si.cbSize ? si.cbSize : (DWORD)(V.W ? V.W * V.H * 2 : 1280 * 720 * 2), &mb); out->AddBuffer(mb); mb->Release(); ob.pSample = out; }
        DWORD st = 0; HRESULT hr = V.dec->ProcessOutput(0, 1, &ob, &st);
        if (hr == MF_E_TRANSFORM_STREAM_CHANGE) { if (ob.pSample) ob.pSample->Release(); setDecOutNV12(); continue; }
        if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr)) { if (ob.pSample) ob.pSample->Release(); break; }
        IMFSample* r = ob.pSample; if (V.W && !V.out.empty()) { IMFMediaBuffer* cb; r->ConvertToContiguousBuffer(&cb); BYTE* p; DWORD ln; cb->Lock(&p, nullptr, &ln); if (ln >= (DWORD)(V.W * V.H * 3 / 2)) { nv12ToBgra(p, V.out.data(), V.W, V.H); g_dbgDecoded++; HDC dc = GetDC(V.hwnd); vpresent(dc); ReleaseDC(V.hwnd, dc); } cb->Unlock(); cb->Release(); }
        r->Release(); }
}
struct Frag { uint16_t count = 0; bool key = false; std::map<uint16_t, std::vector<BYTE>> parts; };
inline std::map<uint32_t, Frag> g_vasm;
inline void vonVideo(const unsigned char* buf, int n) {
    if (n < VHDR) return; uint16_t sid; memcpy(&sid, buf + 1, 2); if (sid == V.myId) return;
    uint32_t fid; memcpy(&fid, buf + 3, 4); uint16_t idx, cnt; memcpy(&idx, buf + 7, 2); memcpy(&cnt, buf + 9, 2); bool key = buf[11] != 0;
    if (fid <= V.lastDone) return;
    Frag& f = g_vasm[fid]; f.count = cnt; f.key = key; f.parts[idx].assign(buf + VHDR, buf + n);
    if ((uint16_t)f.parts.size() == cnt) {
        std::vector<BYTE> frame; for (uint16_t i = 0; i < cnt; ++i) { auto it = f.parts.find(i); if (it == f.parts.end()) return; frame.insert(frame.end(), it->second.begin(), it->second.end()); }
        g_dbgFrames++; if (key) V.started = true; if (V.started) vdecode(frame.data(), frame.size());
        V.lastDone = fid; for (auto it = g_vasm.begin(); it != g_vasm.end();) { if (it->first <= fid) it = g_vasm.erase(it); else ++it; }
    }
    if (g_vasm.size() > 120) g_vasm.erase(g_vasm.begin());
}
inline LRESULT CALLBACK VWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); vpresent(dc); EndPaint(h, &ps); return 0; }
    if (m == WM_DESTROY) { V.run = false; return 0; }
    return DefWindowProcW(h, m, w, l);
}
inline void vSendSub(SOCKET sock) { unsigned char p[4]; p[0] = V_SUB; memcpy(p + 1, &V.myId, 2); p[3] = (unsigned char)V.layer.load(); send(sock, (char*)p, 4, 0); }
inline void viewThread(std::string host, int port, std::string token, std::wstring title, int initialLayer) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED); MFStartup(MF_VERSION);
    V.layer = initialLayer; V.layerChanged = false;
    if (!joinRoom(V.sock, host, port, token, V.myId, V.run)) { if (V.sock != INVALID_SOCKET) closesocket(V.sock); V.sock = INVALID_SOCKET; MFShutdown(); CoUninitialize(); return; }
    static bool cls = false; if (!cls) { WNDCLASSW wc{}; wc.lpfnWndProc = VWndProc; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"MessagerScreenView"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH); RegisterClassW(&wc); cls = true; }
    V.hwnd = CreateWindowExW(0, L"MessagerScreenView", title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 640, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    ShowWindow(V.hwnd, SW_SHOW);
    if (FAILED(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&V.dec)))) { DestroyWindow(V.hwnd); V.hwnd = nullptr; closesocket(V.sock); V.sock = INVALID_SOCKET; MFShutdown(); CoUninitialize(); return; }
    { IMFMediaType* it; MFCreateMediaType(&it); it->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); it->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264); MFSetAttributeSize(it, MF_MT_FRAME_SIZE, 1280, 720); MFSetAttributeRatio(it, MF_MT_FRAME_RATE, 15, 1); it->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); V.dec->SetInputType(0, it, 0); it->Release(); setDecOutNV12(); V.dec->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0); V.dec->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0); }
    char buf[2048]; V.lastPkt = GetTickCount(); DWORD lastPing = GetTickCount(); vSendSub(V.sock);
    while (V.run) {
        MSG msg; while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { if (msg.message == WM_QUIT) { V.run = false; break; } TranslateMessage(&msg); DispatchMessageW(&msg); }
        if (!V.run) break;
        if (V.layerChanged.exchange(false)) { V.started = false; V.lastDone = 0; g_vasm.clear(); vSendSub(V.sock); }   // resync on the new layer's next keyframe
        int n = recv(V.sock, buf, sizeof(buf), 0);
        DWORD now = GetTickCount();
        if (n > 0 && (unsigned char)buf[0] == V_VIDEO) { g_dbgRecv++; vonVideo((unsigned char*)buf, n); V.lastPkt = now; }
        if (now - lastPing > 2000) { unsigned char p[3]; p[0] = V_PING; memcpy(p + 1, &V.myId, 2); send(V.sock, (char*)p, 3, 0); vSendSub(V.sock); lastPing = now; }
        if (V.started && now - V.lastPkt > 6000) break;   // sharer stopped -> auto-close
    }
    if (V.hwnd) { DestroyWindow(V.hwnd); V.hwnd = nullptr; }
    if (V.dec) { V.dec->Release(); V.dec = nullptr; }
    if (V.sock != INVALID_SOCKET) { closesocket(V.sock); V.sock = INVALID_SOCKET; }
    g_vasm.clear(); V.myId = 0; V.W = V.H = 0; V.started = false; V.lastDone = 0; V.out.clear();
    MFShutdown(); CoUninitialize();
}
inline void viewStop() { V.run = false; if (V.thread.joinable()) V.thread.join(); }
inline void viewStart(const std::string& host, int port, const std::string& token, const std::wstring& title, int initialLayer) { viewStop(); if (token.size() != 16) return; V.run = true; V.thread = std::thread(viewThread, host, port, token, title, initialLayer); }
inline void viewSetLayer(int layer) { V.layer = layer; V.layerChanged = true; }
inline bool viewing() { return V.run; }

} // namespace screen
