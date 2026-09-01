// voice_loopback.cpp - Step 1 of Messager voice: prove the audio pipeline.
//
// Captures the default microphone (WASAPI), encodes to Opus, immediately
// decodes it, and plays it back to the default speakers. If it works you hear
// yourself with a short delay. This is entirely local - no network yet.
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 /MT voice_loopback.cpp ^
//            /I sdk\opus\include sdk\opus\lib\opus.lib ole32.lib /Fe:VoiceLoopback.exe
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <atomic>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>
#include "opus.h"

#pragma comment(lib, "ole32.lib")

// 48 kHz mono 16-bit PCM; Opus 20 ms frames = 960 samples.
static const int SR = 48000, CH = 1, FRAME = 960;

static std::atomic<bool> g_run{ true };
static std::mutex g_qmtx;
static std::deque<short> g_playQ;   // decoded PCM waiting to be rendered

static WAVEFORMATEX makeFmt() {
    WAVEFORMATEX f{};
    f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = CH; f.nSamplesPerSec = SR;
    f.wBitsPerSample = 16; f.nBlockAlign = CH * 2; f.nAvgBytesPerSec = SR * f.nBlockAlign;
    f.cbSize = 0; return f;
}
static IAudioClient* initClient(EDataFlow flow, IAudioClient** outClient) {
    IMMDeviceEnumerator* en = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                __uuidof(IMMDeviceEnumerator), (void**)&en))) return nullptr;
    IMMDevice* dev = nullptr;
    en->GetDefaultAudioEndpoint(flow, eConsole, &dev); en->Release();
    if (!dev) return nullptr;
    IAudioClient* c = nullptr;
    dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&c); dev->Release();
    if (!c) return nullptr;
    WAVEFORMATEX fmt = makeFmt();
    DWORD flags = AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    REFERENCE_TIME dur = 1000000; // 100 ms
    if (FAILED(c->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, dur, 0, &fmt, nullptr))) { c->Release(); return nullptr; }
    *outClient = c; return c;
}

static void captureThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = nullptr;
    if (!initClient(eCapture, &c)) { printf("!! could not open microphone\n"); return; }
    IAudioCaptureClient* cap = nullptr;
    c->GetService(__uuidof(IAudioCaptureClient), (void**)&cap);
    OpusEncoder* enc = opus_encoder_create(SR, CH, OPUS_APPLICATION_VOIP, nullptr);
    opus_encoder_ctl(enc, OPUS_SET_BITRATE(28000));
    OpusDecoder* dec = opus_decoder_create(SR, CH, nullptr);
    c->Start();

    std::vector<short> accum;
    unsigned char pkt[4000]; short pcmOut[FRAME];
    while (g_run) {
        UINT32 packet = 0;
        cap->GetNextPacketSize(&packet);
        while (packet > 0 && g_run) {
            BYTE* data = nullptr; UINT32 frames = 0; DWORD fl = 0;
            if (FAILED(cap->GetBuffer(&data, &frames, &fl, nullptr, nullptr))) break;
            const short* s = (const short*)data;
            if (fl & AUDCLNT_BUFFERFLAGS_SILENT) accum.insert(accum.end(), frames, 0);
            else accum.insert(accum.end(), s, s + frames);
            cap->ReleaseBuffer(frames);
            cap->GetNextPacketSize(&packet);
        }
        while (accum.size() >= FRAME) {
            int n = opus_encode(enc, accum.data(), FRAME, pkt, sizeof(pkt));       // -> Opus
            if (n > 0) {
                int got = opus_decode(dec, pkt, n, pcmOut, FRAME, 0);              // Opus -> PCM (loopback)
                if (got > 0) { std::lock_guard<std::mutex> lk(g_qmtx); g_playQ.insert(g_playQ.end(), pcmOut, pcmOut + got); }
            }
            accum.erase(accum.begin(), accum.begin() + FRAME);
        }
        Sleep(5);
    }
    c->Stop(); opus_encoder_destroy(enc); opus_decoder_destroy(dec);
    cap->Release(); c->Release(); CoUninitialize();
}

static void renderThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = nullptr;
    if (!initClient(eRender, &c)) { printf("!! could not open speakers\n"); return; }
    IAudioRenderClient* ren = nullptr;
    c->GetService(__uuidof(IAudioRenderClient), (void**)&ren);
    UINT32 bufFrames = 0; c->GetBufferSize(&bufFrames);
    c->Start();
    while (g_run) {
        UINT32 pad = 0; c->GetCurrentPadding(&pad);
        UINT32 avail = bufFrames - pad;
        if (avail > 0) {
            BYTE* out = nullptr;
            if (SUCCEEDED(ren->GetBuffer(avail, &out))) {
                short* o = (short*)out; UINT32 wrote = 0;
                { std::lock_guard<std::mutex> lk(g_qmtx);
                  while (wrote < avail && !g_playQ.empty()) { o[wrote++] = g_playQ.front(); g_playQ.pop_front(); } }
                for (UINT32 i = wrote; i < avail; ++i) o[i] = 0;   // pad with silence
                ren->ReleaseBuffer(avail, 0);
            }
        }
        Sleep(5);
    }
    c->Stop(); ren->Release(); c->Release(); CoUninitialize();
}

int main() {
    printf("Voice loopback: speak into your mic - you should hear yourself.\n");
    printf("(Use headphones to avoid feedback.)  Press Enter to stop.\n");
    std::thread cap(captureThread), ren(renderThread);
    getchar();
    g_run = false;
    cap.join(); ren.join();
    printf("stopped.\n");
    return 0;
}
