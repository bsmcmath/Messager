// MessagerClient.exe - desktop client for the Messager server.
//
// Hosts the server's actual web page in an embedded Edge WebView2, so the
// layout and functionality are exactly the same as opening the site in a
// browser. The server address lives in a Settings popup (window menu ->
// "Settings", or the button on the offline bar). A red bar appears ONLY when
// the server can't be reached.
//
// Requires the Microsoft Edge WebView2 Runtime (preinstalled on Windows 11).
//
// Build: cl /std:c++17 /utf-8 /EHsc /O2 client.cpp /I sdk\include ^
//            sdk\lib\WebView2LoaderStatic.lib ws2_32.lib ole32.lib oleaut32.lib ^
//            version.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib ^
//            /Fe:MessagerClient.exe /link /SUBSYSTEM:WINDOWS
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <wincrypt.h>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include "WebView2.h"
#include "voice_engine.h"
#include "screen_engine.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#define WM_APP_STATUS  (WM_APP + 1)   // wParam: 1 = online, 0 = offline
#define IDM_SETTINGS   0x0100         // window (system) menu items
#define IDM_RELOAD     0x0110
#define ID_RETRY       3001
#define ID_OPENSET     3002
#define ID_SET_SAVE    3101
#define ID_SET_CANCEL  3102
#define BANNER_H       36

static const wchar_t* DEFAULT_URL = L"http://47.26.185.125:100/";

static HINSTANCE g_hInst;
static HWND g_hwnd = nullptr;
static HWND g_banner = nullptr, g_retryBtn = nullptr, g_setBtn = nullptr;   // offline bar
static HWND g_settingsWin = nullptr, g_setEdit = nullptr;                   // settings popup
static ICoreWebView2Controller* g_controller = nullptr;
static ICoreWebView2* g_webview = nullptr;
static HFONT g_font = nullptr;
static HBRUSH g_redBrush = nullptr;

static std::wstring g_serverUrl;         // current server URL (guarded by g_urlMutex)
static std::mutex g_urlMutex;
static std::atomic<bool> g_offline{ false };
static std::atomic<bool> g_appRunning{ true };
static std::atomic<bool> g_haveStatus{ false };  // got at least one status result

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static std::wstring exeDir() {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s = buf; size_t p = s.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? L"." : s.substr(0, p);
}
static std::wstring cfgPath() { return exeDir() + L"\\messager_client.cfg"; }

static std::wstring loadAddress() {
    std::wifstream f(cfgPath());
    if (f) { std::wstring line; std::getline(f, line);
        while (!line.empty() && (line.back()==L'\r'||line.back()==L'\n'||line.back()==L' ')) line.pop_back();
        if (!line.empty()) return line; }
    return DEFAULT_URL;
}
static void saveAddress(const std::wstring& url) {
    std::wofstream f(cfgPath(), std::ios::trunc);
    if (f) f << url;
}
static std::wstring userDataFolder() {
    wchar_t* base = nullptr; size_t len = 0; _wdupenv_s(&base, &len, L"LOCALAPPDATA");
    std::wstring f = base ? base : exeDir();
    if (base) free(base);
    return f + L"\\MessagerClient";
}
static std::wstring getEditText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring w(n, 0); GetWindowTextW(h, &w[0], n + 1); return w;
}
static std::wstring trimw(std::wstring s) {
    while (!s.empty() && (s.front()==L' '||s.front()==L'\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()==L' '||s.back()==L'\t')) s.pop_back();
    return s;
}
static std::wstring normalizeUrl(std::wstring u) {
    u = trimw(u);
    if (u.empty()) return DEFAULT_URL;
    if (u.find(L"://") == std::wstring::npos) u = L"http://" + u;
    return u;
}
static std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0); WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0); MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ---------------------------------------------------------------------------
// remembered login (encrypted at rest with Windows DPAPI)
// ---------------------------------------------------------------------------
static std::wstring loginPath() { return exeDir() + L"\\messager_client_login.dat"; }
static void saveCreds(const std::string& user, const std::string& pass) {
    std::string plain = user + "\n" + pass;
    DATA_BLOB in{ (DWORD)plain.size(), (BYTE*)plain.data() }, out{};
    if (CryptProtectData(&in, L"MessagerLogin", nullptr, nullptr, nullptr, 0, &out)) {
        std::ofstream f(loginPath(), std::ios::binary | std::ios::trunc);
        f.write((char*)out.pbData, out.cbData);
        LocalFree(out.pbData);
    }
}
static bool loadCreds(std::string& user, std::string& pass) {
    std::ifstream f(loginPath(), std::ios::binary);
    if (!f) return false;
    std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (data.empty()) return false;
    DATA_BLOB in{ (DWORD)data.size(), (BYTE*)data.data() }, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return false;
    std::string plain((char*)out.pbData, out.cbData); LocalFree(out.pbData);
    size_t nl = plain.find('\n'); if (nl == std::string::npos) return false;
    user = plain.substr(0, nl); pass = plain.substr(nl + 1); return true;
}
static void clearCreds() { DeleteFileW(loginPath().c_str()); }

// JSON string-literal escaping (for embedding creds into injected script).
static std::string jsonEsc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break; case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break; case '/': o += "\\/"; break;
            default: if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; } else o += (char)c;
        }
    }
    return o;
}
// Extract a JSON string value for a top-level key from a flat object.
static std::string jsonGet(const std::string& j, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t k = j.find(pat); if (k == std::string::npos) return "";
    size_t c = j.find(':', k + pat.size()); if (c == std::string::npos) return "";
    size_t q = j.find('"', c); if (q == std::string::npos) return "";
    std::string out; ++q;
    for (; q < j.size(); ++q) {
        char ch = j[q];
        if (ch == '\\' && q + 1 < j.size()) {
            char n = j[++q];
            switch (n) { case 'n': out += '\n'; break; case 'r': out += '\r'; break;
                case 't': out += '\t'; break; case '"': out += '"'; break; case '\\': out += '\\'; break;
                case '/': out += '/'; break; case 'b': out += '\b'; break; case 'f': out += '\f'; break;
                case 'u': if (q + 4 < j.size()) { int cp = (int)strtol(j.substr(q + 1, 4).c_str(), nullptr, 16);
                            if (cp < 128) out += (char)cp; q += 4; } break;
                default: out += n; }
        } else if (ch == '"') break;
        else out += ch;
    }
    return out;
}

// Build the script injected into every page load: silently signs in with the
// remembered account, and captures new logins/logouts to remember them.
static std::wstring buildAutoLoginScript() {
    std::string user, pass, credsJson = "null";
    if (loadCreds(user, pass))
        credsJson = "{\"u\":\"" + jsonEsc(user) + "\",\"p\":\"" + jsonEsc(pass) + "\"}";
    std::string js =
        "(function(){var CREDS=" + credsJson + ";var attempted=false,hooked=false,disabled=false;"
        "function st(){return document.body?document.body.getAttribute('data-auth'):null;}"
        "function inn(){return st()==='in';}"
        "function ready(){return !!document.getElementById('authUser')&&st()!==null;}"
        "function hook(){if(hooked)return;"
        "if(typeof window.doAuth==='function'){hooked=true;var od=window.doAuth;window.doAuth=function(){"
        "var u=(document.getElementById('authUser')||{}).value||'';var p=(document.getElementById('authPass')||{}).value||'';"
        "var r=od.apply(this,arguments);Promise.resolve(r).then(function(){setTimeout(function(){if(inn()){try{window.chrome.webview.postMessage(JSON.stringify({type:'login',user:u,pass:p}));}catch(e){}}},300);});return r;};}"
        "if(typeof window.logout==='function'&&!window.__lo){window.__lo=true;var ol=window.logout;window.logout=function(){disabled=true;try{window.chrome.webview.postMessage(JSON.stringify({type:'logout'}));}catch(e){}return ol.apply(this,arguments);};}}"
        "function tick(){hook();if(!disabled&&CREDS&&CREDS.u&&!attempted&&ready()&&!inn()){attempted=true;"
        "document.getElementById('authUser').value=CREDS.u;document.getElementById('authPass').value=CREDS.p||'';"
        "if(typeof window.doAuth==='function')window.doAuth();}}"
        "var n=0,iv=setInterval(function(){tick();if(inn()||++n>40)clearInterval(iv);},250);"
        "document.addEventListener('DOMContentLoaded',tick);})();";
    return widen(js);
}

static std::wstring currentUrl() { std::lock_guard<std::mutex> lk(g_urlMutex); return g_serverUrl; }
static void setCurrentUrl(const std::wstring& u) { std::lock_guard<std::mutex> lk(g_urlMutex); g_serverUrl = u; }

// ---------------------------------------------------------------------------
// reachability check (native, so it detects offline even after loading)
// ---------------------------------------------------------------------------
static bool parseHostPort(const std::wstring& url, std::string& host, int& port) {
    std::wstring u = url;
    size_t s = u.find(L"://"); if (s != std::wstring::npos) u = u.substr(s + 3);
    size_t slash = u.find(L'/'); if (slash != std::wstring::npos) u = u.substr(0, slash);
    int p = 80; std::wstring h;
    size_t colon = u.find(L':');
    if (colon != std::wstring::npos) { h = u.substr(0, colon); p = _wtoi(u.substr(colon + 1).c_str()); }
    else h = u;
    if (h.empty()) return false;
    host = narrow(h); port = (p > 0) ? p : 80; return true;
}
static bool tcpReachable(const std::string& host, int port, int timeoutMs) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr; char ps[16]; sprintf_s(ps, "%d", port);
    if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) return false;
    bool ok = false;
    for (addrinfo* a = res; a && !ok; a = a->ai_next) {
        SOCKET s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        connect(s, a->ai_addr, (int)a->ai_addrlen);
        fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
        timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
        if (select(0, nullptr, &wr, &ex, &tv) > 0 && FD_ISSET(s, &wr)) {
            int err = 0, len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
            if (err == 0) ok = true;
        }
        closesocket(s);
    }
    freeaddrinfo(res);
    return ok;
}
static void checkerLoop() {
    while (g_appRunning) {
        std::string host; int port; bool ok = false;
        if (parseHostPort(currentUrl(), host, port)) ok = tcpReachable(host, port, 3000);
        if (g_hwnd) PostMessageW(g_hwnd, WM_APP_STATUS, ok ? 1 : 0, 0);
        for (int i = 0; i < 40 && g_appRunning; ++i) Sleep(100);   // ~4s, responsive to exit
    }
}

// ---------------------------------------------------------------------------
// navigation + layout
// ---------------------------------------------------------------------------
static void navigateTo(const std::wstring& rawUrl) {
    std::wstring url = normalizeUrl(rawUrl);
    setCurrentUrl(url);
    saveAddress(url);
    if (g_webview) g_webview->Navigate(url.c_str());
}
static void layoutClient(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    bool off = g_offline.load();
    if (off) {
        MoveWindow(g_banner, 0, 0, W, BANNER_H, TRUE);
        MoveWindow(g_setBtn, W - 88, 5, 82, BANNER_H - 10, TRUE);
        MoveWindow(g_retryBtn, W - 88 - 76, 5, 70, BANNER_H - 10, TRUE);
    }
    int top = off ? BANNER_H : 0;
    if (g_controller) { RECT b{ 0, top, W, H }; g_controller->put_Bounds(b); }
}
static void showBanner(bool show) {
    int sw = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_banner, sw); ShowWindow(g_retryBtn, sw); ShowWindow(g_setBtn, sw);
}

// ---------------------------------------------------------------------------
// settings popup
// ---------------------------------------------------------------------------
static LRESULT CALLBACK SettingsProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HWND lbl = CreateWindowW(L"STATIC", L"Server address:", WS_CHILD | WS_VISIBLE,
            16, 16, 360, 20, hwnd, nullptr, g_hInst, nullptr);
        g_setEdit = CreateWindowW(L"EDIT", currentUrl().c_str(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 16, 40, 360, 26, hwnd, nullptr, g_hInst, nullptr);
        HWND save = CreateWindowW(L"BUTTON", L"Save && Connect", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            176, 82, 130, 30, hwnd, (HMENU)ID_SET_SAVE, g_hInst, nullptr);
        HWND cancel = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            314, 82, 62, 30, hwnd, (HMENU)ID_SET_CANCEL, g_hInst, nullptr);
        HWND hint = CreateWindowW(L"STATIC",
            L"e.g. http://server-ip:100/   (leave the http:// and port as given)",
            WS_CHILD | WS_VISIBLE, 16, 122, 360, 34, hwnd, nullptr, g_hInst, nullptr);
        for (HWND c : { lbl, g_setEdit, save, cancel, hint }) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        SetFocus(g_setEdit);
        SendMessageW(g_setEdit, EM_SETSEL, 0, -1);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDCANCEL) { DestroyWindow(hwnd); return 0; }
        if (id == IDOK) id = ID_SET_SAVE;
        if (id == ID_SET_SAVE) { navigateTo(getEditText(g_setEdit)); DestroyWindow(hwnd); return 0; }
        if (id == ID_SET_CANCEL) { DestroyWindow(hwnd); return 0; }
        return 0;
    }
    case DM_GETDEFID: return MAKELRESULT(ID_SET_SAVE, DC_HASDEFID);
    case WM_CLOSE:   DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_settingsWin = nullptr; g_setEdit = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
static void openSettings() {
    if (g_settingsWin) { SetForegroundWindow(g_settingsWin); return; }
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc{}; wc.lpfnWndProc = SettingsProc; wc.hInstance = g_hInst;
        wc.lpszClassName = L"MessagerClientSettings"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        RegisterClassW(&wc); reg = true;
    }
    RECT pr; GetWindowRect(g_hwnd, &pr);
    int w = 410, h = 210;
    int x = pr.left + ((pr.right - pr.left) - w) / 2;
    int y = pr.top + ((pr.bottom - pr.top) - h) / 3;
    g_settingsWin = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_DLGMODALFRAME, L"MessagerClientSettings",
        L"Messager - Settings", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, x, y, w, h,
        g_hwnd, nullptr, g_hInst, nullptr);
    ShowWindow(g_settingsWin, SW_SHOW);
}

// ---------------------------------------------------------------------------
// COM callback handlers
// ---------------------------------------------------------------------------
// Receives {type:'login',user,pass} / {type:'logout'} from the injected script.
class WebMessageHandler : public ICoreWebView2WebMessageReceivedEventHandler {
    LONG m_ref = 1;
public:
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICoreWebView2WebMessageReceivedEventHandler)) {
            *ppv = static_cast<ICoreWebView2WebMessageReceivedEventHandler*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG __stdcall AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG __stdcall Release() override { ULONG r = InterlockedDecrement(&m_ref); if (!r) delete this; return r; }
    HRESULT __stdcall Invoke(ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) override {
        LPWSTR msg = nullptr;
        if (args && SUCCEEDED(args->TryGetWebMessageAsString(&msg)) && msg) {
            std::string s = narrow(msg); CoTaskMemFree(msg);
            std::string type = jsonGet(s, "type");
            if (type == "login") saveCreds(jsonGet(s, "user"), jsonGet(s, "pass"));
            else if (type == "logout") clearCreds();
            else if (type == "voice-join") {
                std::string host; int hp = 0; parseHostPort(currentUrl(), host, hp);
                voice::voiceStart(host, atoi(jsonGet(s, "port").c_str()), jsonGet(s, "token"));
            }
            else if (type == "voice-leave") voice::voiceStop();
            else if (type == "voice-mute")  voice::voiceMute(jsonGet(s, "on") == "1");
            else if (type == "screen-share-start") {
                std::string host; int hp = 0; parseHostPort(currentUrl(), host, hp);
                screen::shareStart(host, atoi(jsonGet(s, "port").c_str()), jsonGet(s, "token"), atoi(jsonGet(s, "quality").c_str()));
            }
            else if (type == "screen-share-stop") screen::shareStop();
            else if (type == "screen-view-start") {
                std::string host; int hp = 0; parseHostPort(currentUrl(), host, hp);
                std::string nm = jsonGet(s, "name"); if (nm.empty()) nm = "screen";
                int wn = MultiByteToWideChar(CP_UTF8, 0, nm.c_str(), -1, nullptr, 0);
                std::wstring wnm(wn > 0 ? wn - 1 : 0, L'\0'); if (wn > 0) MultiByteToWideChar(CP_UTF8, 0, nm.c_str(), -1, &wnm[0], wn);
                screen::viewStart(host, atoi(jsonGet(s, "port").c_str()), jsonGet(s, "token"), L"Screen share \x2014 " + wnm, atoi(jsonGet(s, "layer").c_str()));
            }
            else if (type == "screen-view-stop") screen::viewStop();
            else if (type == "screen-view-quality") screen::viewSetLayer(atoi(jsonGet(s, "layer").c_str()));
        }
        return S_OK;
    }
};

class ControllerHandler : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
    LONG m_ref = 1;
public:
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG __stdcall AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG __stdcall Release() override { ULONG r = InterlockedDecrement(&m_ref); if (!r) delete this; return r; }
    HRESULT __stdcall Invoke(HRESULT result, ICoreWebView2Controller* controller) override {
        if (FAILED(result) || !controller) {
            MessageBoxW(g_hwnd, L"Failed to create the WebView.\nIs the Microsoft Edge WebView2 Runtime installed?",
                        L"Messager Client", MB_ICONERROR);
            return result;
        }
        g_controller = controller; g_controller->AddRef();
        g_controller->get_CoreWebView2(&g_webview);
        if (g_webview) {
            std::wstring script = buildAutoLoginScript();
            g_webview->AddScriptToExecuteOnDocumentCreated(script.c_str(), nullptr);
            EventRegistrationToken tok;
            g_webview->add_WebMessageReceived(new WebMessageHandler(), &tok);
        }
        layoutClient(g_hwnd);
        if (g_webview) g_webview->Navigate(currentUrl().c_str());
        return S_OK;
    }
};
class EnvHandler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
    LONG m_ref = 1;
public:
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler)) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG __stdcall AddRef() override { return InterlockedIncrement(&m_ref); }
    ULONG __stdcall Release() override { ULONG r = InterlockedDecrement(&m_ref); if (!r) delete this; return r; }
    HRESULT __stdcall Invoke(HRESULT result, ICoreWebView2Environment* env) override {
        if (FAILED(result) || !env) {
            MessageBoxW(g_hwnd, L"Could not start the WebView2 environment.\nPlease install the Microsoft Edge WebView2 Runtime.",
                        L"Messager Client", MB_ICONERROR);
            return result;
        }
        env->CreateCoreWebView2Controller(g_hwnd, new ControllerHandler());
        return S_OK;
    }
};

// ---------------------------------------------------------------------------
// main window
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;   // must be set before WebView2 env creation (it pumps messages)
        g_font = CreateFontW(-MulDiv(10, GetDeviceCaps(GetDC(nullptr), LOGPIXELSY), 72), 0, 0, 0,
            FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_redBrush = CreateSolidBrush(RGB(192, 40, 40));

        // Offline bar (hidden until the server is unreachable).
        g_banner = CreateWindowW(L"STATIC", L"  Can't reach the server - retrying...",
            WS_CHILD | SS_CENTERIMAGE, 0, 0, 10, 10, hwnd, nullptr, g_hInst, nullptr);
        g_retryBtn = CreateWindowW(L"BUTTON", L"Retry", WS_CHILD | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd, (HMENU)ID_RETRY, g_hInst, nullptr);
        g_setBtn   = CreateWindowW(L"BUTTON", L"Settings", WS_CHILD | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd, (HMENU)ID_OPENSET, g_hInst, nullptr);
        for (HWND c : { g_banner, g_retryBtn, g_setBtn }) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);

        // Add "Settings" / "Reload" to the window (system) menu.
        HMENU sm = GetSystemMenu(hwnd, FALSE);
        InsertMenuW(sm, 0, MF_BYPOSITION | MF_STRING, IDM_SETTINGS, L"Settings...");
        InsertMenuW(sm, 1, MF_BYPOSITION | MF_STRING, IDM_RELOAD, L"Reload");
        InsertMenuW(sm, 2, MF_BYPOSITION | MF_SEPARATOR, 0, nullptr);

        std::wstring udf = userDataFolder();
        HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(nullptr, udf.c_str(), nullptr, new EnvHandler());
        if (FAILED(hr)) {
            MessageBoxW(hwnd, L"The Microsoft Edge WebView2 Runtime does not appear to be installed.\n\n"
                              L"Install it from Microsoft, then run Messager Client again.",
                        L"Messager Client", MB_ICONERROR);
        }
        std::thread(checkerLoop).detach();
        return 0;
    }
    case WM_SIZE:
        layoutClient(hwnd);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp; mmi->ptMinTrackSize.x = 520; mmi->ptMinTrackSize.y = 400; return 0;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_banner) {
            HDC dc = (HDC)wp; SetBkColor(dc, RGB(192, 40, 40)); SetTextColor(dc, RGB(255, 255, 255));
            return (INT_PTR)g_redBrush;
        }
        break;
    case WM_APP_STATUS: {
        bool off = (wp == 0);
        g_haveStatus = true;
        if (off != g_offline.load()) {
            g_offline = off;
            showBanner(off);
            layoutClient(hwnd);
        }
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == IDM_SETTINGS) { openSettings(); return 0; }
        if ((wp & 0xFFF0) == IDM_RELOAD)   { if (g_webview) g_webview->Reload(); return 0; }
        break;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_RETRY:   if (g_webview) g_webview->Navigate(currentUrl().c_str()); break;
        case ID_OPENSET: openSettings(); break;
        }
        return 0;
    case WM_SETFOCUS:
        if (g_controller) g_controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
        return 0;
    case WM_DESTROY:
        g_appRunning = false;
        voice::voiceStop(); screen::shareStop(); screen::viewStop();
        if (g_controller) { g_controller->Close(); g_controller->Release(); g_controller = nullptr; }
        if (g_webview) { g_webview->Release(); g_webview = nullptr; }
        if (g_font) DeleteObject(g_font);
        if (g_redBrush) DeleteObject(g_redBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInst = hInst;
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_serverUrl = loadAddress();

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"MessagerClient";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, L"MessagerClient", L"Messager",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 760, nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (g_settingsWin) {
            if (msg.hwnd == g_setEdit && msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
                navigateTo(getEditText(g_setEdit)); DestroyWindow(g_settingsWin); continue;
            }
            if (IsDialogMessageW(g_settingsWin, &msg)) continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_appRunning = false;
    CoUninitialize();
    return 0;
}
