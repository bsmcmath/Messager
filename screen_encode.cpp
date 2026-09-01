// screen_encode.cpp - Stage 1b(i): prove H.264 encoding with Media Foundation.
// Captures the screen, converts BGRA->NV12, feeds the MS H.264 encoder MFT, and
// prints stats (frames encoded, byte sizes, keyframes). No decode/display yet -
// this de-risks the encoder before wiring up the rest.
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 screen_encode.cpp d3d11.lib dxgi.lib ^
//   mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib /Fe:ScreenEncode.exe
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
#include <cstdio>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "ole32.lib")

static ID3D11Device* g_dev = nullptr; static ID3D11DeviceContext* g_ctx = nullptr;
static IDXGIOutputDuplication* g_dupl = nullptr; static ID3D11Texture2D* g_staging = nullptr;
static UINT g_texW = 0, g_texH = 0; static std::vector<BYTE> g_bgra;

static bool initCapture() {
    D3D_FEATURE_LEVEL fl;
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, &g_dev, &fl, &g_ctx))) return false;
    IDXGIDevice* dd = nullptr; g_dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dd);
    IDXGIAdapter* ad = nullptr; dd->GetAdapter(&ad); dd->Release();
    IDXGIOutput* o = nullptr; ad->EnumOutputs(0, &o); ad->Release();
    IDXGIOutput1* o1 = nullptr; o->QueryInterface(__uuidof(IDXGIOutput1), (void**)&o1); o->Release();
    HRESULT hr = o1->DuplicateOutput(g_dev, &g_dupl); o1->Release();
    return SUCCEEDED(hr);
}
static bool capture() {
    DXGI_OUTDUPL_FRAME_INFO info{}; IDXGIResource* res = nullptr;
    HRESULT hr = g_dupl->AcquireNextFrame(100, &info, &res);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return false;
    if (FAILED(hr) || !res) return false;
    ID3D11Texture2D* tex = nullptr; res->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&tex); res->Release();
    D3D11_TEXTURE2D_DESC td{}; tex->GetDesc(&td);
    if (!g_staging || td.Width != g_texW || td.Height != g_texH) {
        if (g_staging) g_staging->Release();
        g_texW = td.Width; g_texH = td.Height; g_bgra.resize((size_t)g_texW * g_texH * 4);
        D3D11_TEXTURE2D_DESC d = td; d.Usage = D3D11_USAGE_STAGING; d.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        d.BindFlags = 0; d.MiscFlags = 0; g_dev->CreateTexture2D(&d, nullptr, &g_staging);
    }
    g_ctx->CopyResource(g_staging, tex); tex->Release();
    D3D11_MAPPED_SUBRESOURCE m{};
    if (SUCCEEDED(g_ctx->Map(g_staging, 0, D3D11_MAP_READ, 0, &m))) {
        for (UINT y = 0; y < g_texH; ++y) memcpy(&g_bgra[(size_t)y * g_texW * 4], (BYTE*)m.pData + (size_t)y * m.RowPitch, (size_t)g_texW * 4);
        g_ctx->Unmap(g_staging, 0);
    }
    g_dupl->ReleaseFrame();
    return true;
}
// BGRA (packed) -> NV12 (BT.601 limited range).
static void bgraToNV12(const BYTE* bgra, UINT w, UINT h, BYTE* nv12) {
    BYTE* Y = nv12; BYTE* UV = nv12 + (size_t)w * h;
    for (UINT y = 0; y < h; ++y) for (UINT x = 0; x < w; ++x) {
        const BYTE* p = bgra + ((size_t)y * w + x) * 4;
        int B = p[0], G = p[1], R = p[2];
        Y[(size_t)y * w + x] = (BYTE)((66 * R + 129 * G + 25 * B + 128 >> 8) + 16);
    }
    for (UINT y = 0; y < h; y += 2) for (UINT x = 0; x < w; x += 2) {
        const BYTE* p = bgra + ((size_t)y * w + x) * 4;
        int B = p[0], G = p[1], R = p[2];
        int U = (-38 * R - 74 * G + 112 * B + 128 >> 8) + 128;
        int V = (112 * R - 94 * G - 18 * B + 128 >> 8) + 128;
        BYTE* d = UV + (size_t)(y / 2) * w + (x);
        d[0] = (BYTE)U; d[1] = (BYTE)V;
    }
}

int main() {
    if (FAILED(MFStartup(MF_VERSION))) { printf("MFStartup failed\n"); return 1; }
    if (!initCapture()) { printf("!! capture init failed\n"); return 1; }
    // grab one frame to learn the resolution
    for (int i = 0; i < 50 && g_texW == 0; ++i) capture();
    if (g_texW == 0) { printf("!! no frame captured\n"); return 1; }
    const UINT W = g_texW, H = g_texH, FPS = 30, BR = 4000000;
    printf("screen %ux%u -> H.264 %u fps %u bps\n", W, H, FPS, BR);

    IMFTransform* enc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&enc)))) { printf("!! no H264 encoder\n"); return 1; }
    IMFMediaType* ot = nullptr; MFCreateMediaType(&ot);
    ot->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); ot->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    ot->SetUINT32(MF_MT_AVG_BITRATE, BR); MFSetAttributeSize(ot, MF_MT_FRAME_SIZE, W, H);
    MFSetAttributeRatio(ot, MF_MT_FRAME_RATE, FPS, 1); ot->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    MFSetAttributeRatio(ot, MF_MT_PIXEL_ASPECT_RATIO, 1, 1); ot->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
    HRESULT hro = enc->SetOutputType(0, ot, 0);
    IMFMediaType* it = nullptr; MFCreateMediaType(&it);
    it->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video); it->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
    MFSetAttributeSize(it, MF_MT_FRAME_SIZE, W, H); MFSetAttributeRatio(it, MF_MT_FRAME_RATE, FPS, 1);
    it->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive); MFSetAttributeRatio(it, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    HRESULT hri = enc->SetInputType(0, it, 0);
    printf("SetOutputType=0x%08X SetInputType=0x%08X\n", (unsigned)hro, (unsigned)hri);
    if (FAILED(hro) || FAILED(hri)) { printf("!! type negotiation failed\n"); return 1; }
    enc->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    enc->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);

    const size_t nvSize = (size_t)W * H * 3 / 2;
    std::vector<BYTE> nv12(nvSize);
    MFT_OUTPUT_STREAM_INFO si{}; enc->GetOutputStreamInfo(0, &si);
    long long frames = 0, encoded = 0, keys = 0, totalBytes = 0;
    LONGLONG t = 0; const LONGLONG dur = 10000000LL / FPS;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 3000) {
        if (!capture()) { Sleep(1); continue; }
        frames++;
        bgraToNV12(g_bgra.data(), W, H, nv12.data());
        IMFSample* in = nullptr; MFCreateSample(&in);
        IMFMediaBuffer* ib = nullptr; MFCreateMemoryBuffer((DWORD)nvSize, &ib);
        BYTE* p = nullptr; DWORD mx = 0; ib->Lock(&p, &mx, nullptr); memcpy(p, nv12.data(), nvSize); ib->Unlock(); ib->SetCurrentLength((DWORD)nvSize);
        in->AddBuffer(ib); ib->Release(); in->SetSampleTime(t); in->SetSampleDuration(dur); t += dur;
        enc->ProcessInput(0, in, 0); in->Release();
        // drain
        while (true) {
            MFT_OUTPUT_DATA_BUFFER ob{}; IMFSample* out = nullptr;
            bool alloc = !(si.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES);
            if (alloc) { MFCreateSample(&out); IMFMediaBuffer* obf = nullptr; MFCreateMemoryBuffer(si.cbSize ? si.cbSize : (DWORD)nvSize, &obf); out->AddBuffer(obf); obf->Release(); ob.pSample = out; }
            DWORD st = 0; HRESULT hr = enc->ProcessOutput(0, 1, &ob, &st);
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) { if (out) out->Release(); break; }
            if (FAILED(hr)) { if (out) out->Release(); break; }
            IMFSample* r = ob.pSample; DWORD len = 0; r->GetTotalLength(&len);
            UINT32 clean = 0; r->GetUINT32(MFSampleExtension_CleanPoint, &clean);
            encoded++; totalBytes += len; if (clean) keys++;
            r->Release();
        }
    }
    printf("captured=%lld  encoded=%lld frames  keyframes=%lld  totalBytes=%lld  avg=%lld bytes/frame\n",
           frames, encoded, keys, totalBytes, encoded ? totalBytes / encoded : 0);
    enc->Release(); MFShutdown();
    return 0;
}
