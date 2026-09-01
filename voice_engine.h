// voice_engine.h - native voice engine embedded in MessagerClient.
// Mic -> Opus -> UDP to the server relay; UDP in -> per-sender decode -> mix ->
// speakers. Controlled by voiceStart / voiceStop / voiceMute. Assumes winsock2,
// windows.h, and WSAStartup have already happened (client.cpp does that).
#pragma once
#include <ws2tcpip.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "opus.h"

namespace voice {

static const int SR = 48000, CH = 1, FRAME = 960;
static const unsigned char V_HELLO = 0x01, V_WELCOME = 0x02, V_AUDIO = 0x03, V_PING = 0x04;

inline SOCKET      g_sock = INVALID_SOCKET;
inline uint16_t    g_myId = 0;
inline std::atomic<bool> g_run{ false };
inline std::atomic<bool> g_muted{ false };
inline std::mutex  g_bufMtx;
inline std::map<uint16_t, std::deque<short>> g_senderBufs;
inline std::thread g_setup, g_cap, g_recv, g_ren;

inline WAVEFORMATEX vfmt() {
    WAVEFORMATEX f{}; f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = CH; f.nSamplesPerSec = SR;
    f.wBitsPerSample = 16; f.nBlockAlign = CH * 2; f.nAvgBytesPerSec = SR * f.nBlockAlign; return f;
}
inline IAudioClient* vopen(EDataFlow flow) {
    IMMDeviceEnumerator* en = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                __uuidof(IMMDeviceEnumerator), (void**)&en))) return nullptr;
    IMMDevice* dev = nullptr; en->GetDefaultAudioEndpoint(flow, eConsole, &dev); en->Release();
    if (!dev) return nullptr;
    IAudioClient* c = nullptr; dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&c); dev->Release();
    if (!c) return nullptr;
    WAVEFORMATEX fmt = vfmt();
    DWORD fl = AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    if (FAILED(c->Initialize(AUDCLNT_SHAREMODE_SHARED, fl, 1000000, 0, &fmt, nullptr))) { c->Release(); return nullptr; }
    return c;
}

inline void captureThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = vopen(eCapture);
    if (!c) return;
    IAudioCaptureClient* cap = nullptr; c->GetService(__uuidof(IAudioCaptureClient), (void**)&cap);
    OpusEncoder* enc = opus_encoder_create(SR, CH, OPUS_APPLICATION_VOIP, nullptr);
    opus_encoder_ctl(enc, OPUS_SET_BITRATE(28000));
    c->Start();
    std::vector<short> accum; unsigned char pkt[1500]; uint16_t seq = 0; DWORD lastPing = GetTickCount();
    while (g_run) {
        UINT32 pk = 0; cap->GetNextPacketSize(&pk);
        while (pk > 0 && g_run) {
            BYTE* d = nullptr; UINT32 fr = 0; DWORD flg = 0;
            if (FAILED(cap->GetBuffer(&d, &fr, &flg, nullptr, nullptr))) break;
            const short* s = (const short*)d;
            if (flg & AUDCLNT_BUFFERFLAGS_SILENT) accum.insert(accum.end(), fr, 0);
            else accum.insert(accum.end(), s, s + fr);
            cap->ReleaseBuffer(fr); cap->GetNextPacketSize(&pk);
        }
        while (accum.size() >= FRAME) {
            if (!g_muted) {
                unsigned char body[1400];
                int n = opus_encode(enc, accum.data(), FRAME, body, sizeof(body));
                if (n > 0) { pkt[0] = V_AUDIO; memcpy(pkt + 1, &g_myId, 2); memcpy(pkt + 3, &seq, 2);
                    uint16_t ln = (uint16_t)n; memcpy(pkt + 5, &ln, 2); memcpy(pkt + 7, body, n);
                    send(g_sock, (char*)pkt, 7 + n, 0); seq++; }
            }
            accum.erase(accum.begin(), accum.begin() + FRAME);
        }
        if (GetTickCount() - lastPing > 2000) { unsigned char p[3]; p[0] = V_PING; memcpy(p + 1, &g_myId, 2); send(g_sock, (char*)p, 3, 0); lastPing = GetTickCount(); }
        Sleep(5);
    }
    c->Stop(); opus_encoder_destroy(enc); cap->Release(); c->Release(); CoUninitialize();
}
inline void recvThread() {
    std::map<uint16_t, OpusDecoder*> decs; char buf[2048]; short pcm[FRAME];
    while (g_run) {
        int n = recv(g_sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if ((unsigned char)buf[0] == V_AUDIO && n >= 7) {
            uint16_t sid; memcpy(&sid, buf + 1, 2);
            if (sid == g_myId) continue;
            OpusDecoder*& d = decs[sid]; if (!d) d = opus_decoder_create(SR, CH, nullptr);
            int got = opus_decode(d, (unsigned char*)buf + 7, n - 7, pcm, FRAME, 0);
            if (got > 0) { std::lock_guard<std::mutex> lk(g_bufMtx); g_senderBufs[sid].insert(g_senderBufs[sid].end(), pcm, pcm + got); }
        }
    }
    for (auto& kv : decs) opus_decoder_destroy(kv.second);
}
inline void renderThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = vopen(eRender);
    if (!c) return;
    IAudioRenderClient* ren = nullptr; c->GetService(__uuidof(IAudioRenderClient), (void**)&ren);
    UINT32 bufFrames = 0; c->GetBufferSize(&bufFrames); c->Start();
    while (g_run) {
        UINT32 pad = 0; c->GetCurrentPadding(&pad); UINT32 avail = bufFrames - pad;
        if (avail > 0) { BYTE* out = nullptr;
            if (SUCCEEDED(ren->GetBuffer(avail, &out))) {
                short* o = (short*)out; std::lock_guard<std::mutex> lk(g_bufMtx);
                for (UINT32 i = 0; i < avail; ++i) { int mix = 0;
                    for (auto& kv : g_senderBufs) if (!kv.second.empty()) { mix += kv.second.front(); kv.second.pop_front(); }
                    if (mix > 32767) mix = 32767; if (mix < -32768) mix = -32768; o[i] = (short)mix; }
                ren->ReleaseBuffer(avail, 0);
            }
        }
        Sleep(5);
    }
    c->Stop(); ren->Release(); c->Release(); CoUninitialize();
}

inline void voiceStop() {
    g_run = false;
    if (g_sock != INVALID_SOCKET) { closesocket(g_sock); g_sock = INVALID_SOCKET; }
    if (g_setup.joinable()) g_setup.join();
    if (g_cap.joinable()) g_cap.join();
    if (g_recv.joinable()) g_recv.join();
    if (g_ren.joinable()) g_ren.join();
    g_myId = 0; g_muted = false;
    std::lock_guard<std::mutex> lk(g_bufMtx); g_senderBufs.clear();
}
inline void voiceStart(const std::string& host, int port, const std::string& token) {
    voiceStop();
    if (token.size() != 16) return;
    g_run = true;
    g_setup = std::thread([host, port, token]() {
        addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; addrinfo* res = nullptr;
        char ps[16]; sprintf_s(ps, "%d", port);
        if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) { g_run = false; return; }
        g_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        connect(g_sock, res->ai_addr, (int)res->ai_addrlen); freeaddrinfo(res);
        DWORD tmo = 500; setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));
        char hello[17]; hello[0] = V_HELLO; memcpy(hello + 1, token.data(), 16);
        for (int t = 0; t < 10 && g_myId == 0 && g_run; ++t) {
            send(g_sock, hello, 17, 0);
            char r[8]; int n = recv(g_sock, r, sizeof(r), 0);
            if (n >= 3 && (unsigned char)r[0] == V_WELCOME) memcpy(&g_myId, r + 1, 2);
        }
        if (g_myId == 0) { g_run = false; return; }
        g_cap = std::thread(captureThread); g_recv = std::thread(recvThread); g_ren = std::thread(renderThread);
    });
}
inline void voiceMute(bool on) { g_muted = on; }
inline bool voiceActive() { return g_run && g_myId != 0; }

} // namespace voice
