// voice_net.cpp - Step 2 of Messager voice: real audio over the network.
//
// Captures the mic, Opus-encodes, and sends UDP AUDIO to the server's voice
// relay; receives other people's frames, decodes each sender separately, mixes
// them, and plays the result. This is the whole native voice engine, minus the
// UI wiring. The HTTP join (which yields the token) is done by the caller and
// passed in, exactly as the real client will pass it from the web UI.
//
//   VoiceNet.exe <serverHost> <udpPort> <voiceToken> [runSeconds]
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 /MT voice_net.cpp /I sdk\opus\include ^
//   sdk\opus\lib\opus.lib ole32.lib ws2_32.lib /Fe:VoiceNet.exe /link /NODEFAULTLIB:MSVCRT /IGNORE:4049,4217,4286
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include "opus.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")

static const int SR = 48000, CH = 1, FRAME = 960;
static const unsigned char V_HELLO = 0x01, V_WELCOME = 0x02, V_AUDIO = 0x03, V_PING = 0x04;

static SOCKET g_sock = INVALID_SOCKET;
static uint16_t g_myId = 0;
static std::atomic<bool> g_run{ true };
static std::atomic<long long> g_sent{ 0 }, g_recvd{ 0 };

static std::mutex g_bufMtx;
static std::map<uint16_t, std::deque<short>> g_senderBufs;   // remote id -> jittered PCM
static std::set<uint16_t> g_heard;

static WAVEFORMATEX makeFmt() {
    WAVEFORMATEX f{}; f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = CH; f.nSamplesPerSec = SR;
    f.wBitsPerSample = 16; f.nBlockAlign = CH * 2; f.nAvgBytesPerSec = SR * f.nBlockAlign; return f;
}
static IAudioClient* initClient(EDataFlow flow) {
    IMMDeviceEnumerator* en = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                __uuidof(IMMDeviceEnumerator), (void**)&en))) return nullptr;
    IMMDevice* dev = nullptr; en->GetDefaultAudioEndpoint(flow, eConsole, &dev); en->Release();
    if (!dev) return nullptr;
    IAudioClient* c = nullptr; dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&c); dev->Release();
    if (!c) return nullptr;
    WAVEFORMATEX fmt = makeFmt();
    DWORD flags = AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    if (FAILED(c->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, 1000000, 0, &fmt, nullptr))) { c->Release(); return nullptr; }
    return c;
}

// mic -> Opus -> UDP; also emits keepalive PINGs
static void captureThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = initClient(eCapture);
    if (!c) { printf("!! no microphone\n"); return; }
    IAudioCaptureClient* cap = nullptr; c->GetService(__uuidof(IAudioCaptureClient), (void**)&cap);
    OpusEncoder* enc = opus_encoder_create(SR, CH, OPUS_APPLICATION_VOIP, nullptr);
    opus_encoder_ctl(enc, OPUS_SET_BITRATE(28000));
    c->Start();
    std::vector<short> accum; unsigned char pkt[1500]; uint16_t seq = 0;
    DWORD lastPing = GetTickCount();
    while (g_run) {
        UINT32 packet = 0; cap->GetNextPacketSize(&packet);
        while (packet > 0 && g_run) {
            BYTE* data = nullptr; UINT32 frames = 0; DWORD fl = 0;
            if (FAILED(cap->GetBuffer(&data, &frames, &fl, nullptr, nullptr))) break;
            const short* s = (const short*)data;
            if (fl & AUDCLNT_BUFFERFLAGS_SILENT) accum.insert(accum.end(), frames, 0);
            else accum.insert(accum.end(), s, s + frames);
            cap->ReleaseBuffer(frames); cap->GetNextPacketSize(&packet);
        }
        while (accum.size() >= FRAME) {
            unsigned char body[1400];
            int n = opus_encode(enc, accum.data(), FRAME, body, sizeof(body));
            if (n > 0) {
                pkt[0] = V_AUDIO; memcpy(pkt + 1, &g_myId, 2); memcpy(pkt + 3, &seq, 2);
                uint16_t ln = (uint16_t)n; memcpy(pkt + 5, &ln, 2); memcpy(pkt + 7, body, n);
                send(g_sock, (char*)pkt, 7 + n, 0); g_sent++; seq++;
            }
            accum.erase(accum.begin(), accum.begin() + FRAME);
        }
        if (GetTickCount() - lastPing > 2000) {
            unsigned char p[3]; p[0] = V_PING; memcpy(p + 1, &g_myId, 2); send(g_sock, (char*)p, 3, 0);
            lastPing = GetTickCount();
        }
        Sleep(5);
    }
    c->Stop(); opus_encoder_destroy(enc); cap->Release(); c->Release(); CoUninitialize();
}

// UDP in -> per-sender Opus decode -> per-sender jitter buffer
static void recvThread() {
    std::map<uint16_t, OpusDecoder*> decoders;
    char buf[2048]; short pcm[FRAME];
    while (g_run) {
        int n = recv(g_sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if ((unsigned char)buf[0] == V_AUDIO && n >= 7) {
            uint16_t sid; memcpy(&sid, buf + 1, 2);
            if (sid == g_myId) continue;
            OpusDecoder*& d = decoders[sid];
            if (!d) d = opus_decoder_create(SR, CH, nullptr);
            int got = opus_decode(d, (unsigned char*)buf + 7, n - 7, pcm, FRAME, 0);
            if (got > 0) { std::lock_guard<std::mutex> lk(g_bufMtx);
                g_senderBufs[sid].insert(g_senderBufs[sid].end(), pcm, pcm + got);
                g_heard.insert(sid); g_recvd++; }
        }
    }
    for (auto& kv : decoders) opus_decoder_destroy(kv.second);
}

// mix all senders -> speakers
static void renderThread() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IAudioClient* c = initClient(eRender);
    if (!c) { printf("!! no speakers\n"); return; }
    IAudioRenderClient* ren = nullptr; c->GetService(__uuidof(IAudioRenderClient), (void**)&ren);
    UINT32 bufFrames = 0; c->GetBufferSize(&bufFrames); c->Start();
    while (g_run) {
        UINT32 pad = 0; c->GetCurrentPadding(&pad); UINT32 avail = bufFrames - pad;
        if (avail > 0) {
            BYTE* out = nullptr;
            if (SUCCEEDED(ren->GetBuffer(avail, &out))) {
                short* o = (short*)out;
                std::lock_guard<std::mutex> lk(g_bufMtx);
                for (UINT32 i = 0; i < avail; ++i) {
                    int mix = 0;
                    for (auto& kv : g_senderBufs) if (!kv.second.empty()) { mix += kv.second.front(); kv.second.pop_front(); }
                    if (mix > 32767) mix = 32767; if (mix < -32768) mix = -32768;
                    o[i] = (short)mix;
                }
                ren->ReleaseBuffer(avail, 0);
            }
        }
        Sleep(5);
    }
    c->Stop(); ren->Release(); c->Release(); CoUninitialize();
}

int main(int argc, char** argv) {
    if (argc < 4) { printf("usage: VoiceNet.exe <host> <udpPort> <token> [seconds]\n"); return 1; }
    const char* host = argv[1]; const char* port = argv[2]; std::string token = argv[3];
    int seconds = (argc >= 5) ? atoi(argv[4]) : 0;

    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; addrinfo* res = nullptr;
    if (getaddrinfo(host, port, &hints, &res) != 0) { printf("!! bad host\n"); return 1; }
    g_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(g_sock, res->ai_addr, (int)res->ai_addrlen); freeaddrinfo(res);
    DWORD tmo = 500; setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmo, sizeof(tmo));

    // HELLO -> WELCOME
    if (token.size() != 16) { printf("!! token must be 16 chars\n"); return 1; }
    char hello[17]; hello[0] = V_HELLO; memcpy(hello + 1, token.data(), 16);
    for (int tries = 0; tries < 10 && g_myId == 0 && g_run; ++tries) {
        send(g_sock, hello, 17, 0);
        char r[8]; int n = recv(g_sock, r, sizeof(r), 0);
        if (n >= 3 && (unsigned char)r[0] == V_WELCOME) { memcpy(&g_myId, r + 1, 2); }
    }
    if (g_myId == 0) { printf("!! no WELCOME from server (join/token problem)\n"); return 1; }
    printf("joined voice, my senderId=%u\n", g_myId);

    std::thread cap(captureThread), rc(recvThread), rn(renderThread);
    if (seconds > 0) { Sleep(seconds * 1000); }
    else { printf("talking... press Enter to leave.\n"); getchar(); }
    g_run = false;
    cap.join(); rc.join(); rn.join();

    std::string heardStr; { std::lock_guard<std::mutex> lk(g_bufMtx); for (uint16_t id : g_heard) heardStr += std::to_string(id) + " "; }
    printf("summary: sent=%lld received=%lld heardSenders=[ %s]\n",
           (long long)g_sent, (long long)g_recvd, heardStr.c_str());
    closesocket(g_sock); WSACleanup();
    return 0;
}
