// admin.cpp - Messager desktop control panel (Win32 GUI).
//
// Hosts the Messager server in-process (replaces the console), shows the
// public IP people connect to, and provides full client + moderation tools.
//
// Build: cl /std:c++17 /EHsc /O2 admin.cpp ws2_32.lib bcrypt.lib comctl32.lib ^
//            wininet.lib shell32.lib user32.lib gdi32.lib /Fe:MessagerAdmin.exe ^
//            /link /SUBSYSTEM:WINDOWS
#define UNICODE
#define _UNICODE
#include "messager_core.h"
#include <commctrl.h>
#include <wininet.h>
#include <shellapi.h>
#include <uxtheme.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "uxtheme.lib")

// Common Controls v6 (themed buttons / list views) now comes from the embedded
// application manifest (res_admin.rc -> messager.manifest).

// palette
#define COL_BG        RGB(249, 250, 252)
#define COL_TEXT      RGB(28, 32, 38)
#define COL_HEADER    RGB(120, 126, 136)
#define COL_LINK      RGB(37, 99, 235)
#define COL_RUNNING   RGB(22, 128, 60)
#define COL_STOPPED   RGB(176, 64, 64)

// ---- control IDs ----
#define ID_STARTSTOP   1001
#define ID_COPYURL     1002
#define ID_NEWTHREAD   1003
#define ID_POST        1004
#define ID_USERS       1005
#define ID_THREADS     1006
#define ID_MESSAGES    1007
#define ID_INPUT       1008
#define ID_NEWTITLE    1009
#define ID_LOG         1010
#define ID_PORT        1011
#define ID_OPENBROWSER 1013
#define ID_ACCOUNT     1014
#define ID_APPLYPORT   1015
#define ID_TIMER       1
#define IDM_DELETE     2001
#define IDM_PIN        2002

#define ID_AC_LOGIN    3101
#define ID_AC_REGISTER 3102
#define ID_AC_LOGOUT   3103

#define WM_TRAYICON    (WM_APP + 1)
#define IDM_TRAY_SHOW  4001
#define IDM_TRAY_QUIT  4002

#define ID_U_LV      3001
#define ID_U_BAN     3002
#define ID_U_UNBAN   3003
#define ID_U_PROMOTE 3004
#define ID_U_DEMOTE  3005
#define ID_U_DELETE  3006
#define ID_U_REFRESH 3007

// ---- globals ----
static HINSTANCE g_hInst;
static HWND g_main, g_startBtn, g_portEdit, g_applyBtn, g_urlEdit, g_status, g_copyBtn, g_openBtn, g_usersBtn;
static HWND g_threadsLV, g_msgLV, g_input, g_postBtn, g_newTitle, g_newBtn, g_log;
static HWND g_lblShare, g_lblThreads, g_lblMessages, g_lblLog, g_lblPort;
static HWND g_acctLabel, g_acctBtn;
static HWND g_usersWin = nullptr, g_usersLV = nullptr;

static std::string g_account;          // signed-in account for this panel ("" = none)
static HWND g_acctWin = nullptr, g_acUser = nullptr, g_acPass = nullptr, g_acStatus = nullptr;

static NOTIFYICONDATAW g_nid = {};     // system-tray (hidden-icons) icon
static bool g_trayAdded = false, g_toldAboutTray = false;
static void setTrayTip(const std::wstring& tip);   // defined below, used by updateServerUI

static HFONT g_font = nullptr, g_fontHdr = nullptr;
static HBRUSH g_bgBrush = nullptr;
static std::vector<HWND> g_headerLabels;

static long long g_curThread = -1;
static std::mutex g_ipMutex;
static std::string g_publicIP;         // fetched external IP ("" until known)
static std::atomic<bool> g_ipFetching{false};
static std::string g_connectURL;       // full shareable URL

static unsigned long long g_sigThreads = 0, g_sigMsgs = 0;
static long long g_sigMsgThread = -2;

// ---- string helpers ----
static std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static std::string narrow(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::string getEditText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring w(n, 0);
    GetWindowTextW(h, &w[0], n + 1);
    return narrow(w);
}
static std::string fmtTime(long long epoch) {
    time_t t = (time_t)epoch; struct tm tmv; localtime_s(&tmv, &t);
    char b[32]; snprintf(b, sizeof(b), "%02d-%02d %02d:%02d",
        tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min);
    return b;
}
static std::string oneLine(std::string s) {
    for (auto& c : s) if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    return s;
}

// ---- external IP fetch ----
static std::string httpGet(const char* url) {
    HINTERNET hi = InternetOpenA("Messager", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hi) return "";
    HINTERNET hu = InternetOpenUrlA(hi, url, nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hu) { InternetCloseHandle(hi); return ""; }
    std::string out; char buf[512]; DWORD n = 0;
    while (InternetReadFile(hu, buf, sizeof(buf), &n) && n > 0) out.append(buf, n);
    InternetCloseHandle(hu); InternetCloseHandle(hi);
    return out;
}
static void fetchPublicIP() {
    if (g_ipFetching.exchange(true)) return;
    std::thread([]{
        std::string ip = trimStr(httpGet("http://api.ipify.org"));
        // basic sanity: should look like an IPv4
        bool ok = !ip.empty() && ip.size() <= 45 &&
                  ip.find_first_not_of("0123456789.:abcdefABCDEF") == std::string::npos;
        { std::lock_guard<std::mutex> lk(g_ipMutex); g_publicIP = ok ? ip : ""; }
        g_ipFetching = false;
    }).detach();
}

// ---- ListView helpers ----
static void lvAddColumn(HWND lv, int i, const wchar_t* text, int width) {
    LVCOLUMNW c{}; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = (LPWSTR)text; c.cx = width; c.iSubItem = i;
    ListView_InsertColumn(lv, i, &c);
}
static long long lvSelectedParam(HWND lv) {
    int i = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (i < 0) return -1;
    LVITEMW it{}; it.mask = LVIF_PARAM; it.iItem = i;
    ListView_GetItem(lv, &it);
    return (long long)it.lParam;
}
static int lvInsert(HWND lv, int row, const std::string& text, long long param) {
    std::wstring w = widen(text);
    LVITEMW it{}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = row;
    it.pszText = (LPWSTR)w.c_str(); it.lParam = (LPARAM)param;
    return ListView_InsertItem(lv, &it);
}
static void lvSetSub(HWND lv, int row, int col, const std::string& text) {
    std::wstring w = widen(text);
    ListView_SetItemText(lv, row, col, (LPWSTR)w.c_str());
}
static void lvSelectByParam(HWND lv, long long param) {
    int n = ListView_GetItemCount(lv);
    for (int i = 0; i < n; ++i) {
        LVITEMW it{}; it.mask = LVIF_PARAM; it.iItem = i; ListView_GetItem(lv, &it);
        if ((long long)it.lParam == param) {
            ListView_SetItemState(lv, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            return;
        }
    }
}
static unsigned long long fnvMix(unsigned long long h, unsigned long long x) {
    h ^= x; h *= 1099511628211ULL; return h;
}
static HFONT makeFont(int pt, int weight) {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(pt, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    return CreateFontW(h, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}
static HWND makeHeader(HWND parent, const wchar_t* text) {
    HWND h = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
        0, 0, 10, 10, parent, nullptr, g_hInst, nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)g_fontHdr, TRUE);
    g_headerLabels.push_back(h);
    return h;
}

// ---- refresh UI from core ----
static void refreshThreads() {
    auto ts = listThreads();
    unsigned long long sig = 1469598103934665603ULL;
    for (auto& t : ts) { sig = fnvMix(sig, (unsigned long long)t.id);
        sig = fnvMix(sig, std::hash<std::string>{}(t.title)); sig = fnvMix(sig, t.pinned ? 3 : 7); }
    sig = fnvMix(sig, ts.size());
    if (sig == g_sigThreads) return;
    g_sigThreads = sig;

    long long sel = lvSelectedParam(g_threadsLV);
    SendMessageW(g_threadsLV, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_threadsLV);
    int row = 0;
    for (auto& t : ts) {
        lvInsert(g_threadsLV, row, (t.pinned ? "\xF0\x9F\x93\x8C " : "") + t.title, t.id);
        lvSetSub(g_threadsLV, row, 1, t.author);
        ++row;
    }
    if (sel >= 0) lvSelectByParam(g_threadsLV, sel);
    SendMessageW(g_threadsLV, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_threadsLV, nullptr, TRUE);
}
static void refreshMessages(bool force = false) {
    auto ms = listMessages(g_curThread);
    unsigned long long sig = 1469598103934665603ULL;
    for (auto& m : ms) { sig = fnvMix(sig, (unsigned long long)m.id);
        sig = fnvMix(sig, std::hash<std::string>{}(m.content)); sig = fnvMix(sig, m.pinned ? 3 : 7); }
    sig = fnvMix(sig, ms.size());
    if (!force && sig == g_sigMsgs && g_sigMsgThread == g_curThread) return;
    g_sigMsgs = sig; g_sigMsgThread = g_curThread;

    SendMessageW(g_msgLV, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_msgLV);
    int row = 0;
    for (auto& m : ms) {
        lvInsert(g_msgLV, row, (m.pinned ? "\xF0\x9F\x93\x8C " : "") + fmtTime(m.created), m.id);
        lvSetSub(g_msgLV, row, 1, m.author);
        lvSetSub(g_msgLV, row, 2, oneLine(m.content));
        ++row;
    }
    SendMessageW(g_msgLV, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_msgLV, nullptr, TRUE);
}
static void appendLog(const std::string& line) {
    // keep the edit control from growing without bound
    int len = GetWindowTextLengthW(g_log);
    if (len > 60000) SetWindowTextW(g_log, L"");
    std::wstring w = widen(line + "\r\n");
    SendMessageW(g_log, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)w.c_str());
}

static void updateServerUI() {
    bool running = g_running.load();
    SetWindowTextW(g_startBtn, running ? L"Stop server" : L"Start server");

    std::string ip;
    { std::lock_guard<std::mutex> lk(g_ipMutex); ip = g_publicIP; }

    std::ostringstream st;
    if (running) {
        st << "RUNNING on port " << g_port
           << "   |   accounts: " << userCount()
           << "   |   online: " << onlineCount();
    } else {
        st << "STOPPED";
    }
    SetWindowTextW(g_status, widen(st.str()).c_str());

    std::string url;
    if (running) {
        std::string shownIp = ip.empty() ? std::string("<fetching public IP...>") : ip;
        url = "http://" + shownIp + ":" + std::to_string(g_port) + "/";
    } else {
        url = "(server stopped)";
    }
    if (url != g_connectURL) { g_connectURL = url; SetWindowTextW(g_urlEdit, widen(url).c_str()); }

    // tray tooltip reflects the current state
    static std::wstring lastTip;
    std::wstring tip = running ? (L"Messager - running on port " + std::to_wstring(g_port))
                               : std::wstring(L"Messager - stopped");
    if (tip != lastTip) { lastTip = tip; setTrayTip(tip); }

    // account state
    if (!g_account.empty() && !coreUserExists(g_account)) g_account.clear();
    bool signedIn = !g_account.empty();
    static std::string lastAcct = "\x01";
    if (g_account != lastAcct) {
        lastAcct = g_account;
        SetWindowTextW(g_acctLabel, signedIn
            ? widen("Posting as  @" + g_account).c_str()
            : L"Not signed in - you must sign in to post.");
        SetWindowTextW(g_acctBtn, signedIn ? L"Switch / sign out" : L"Sign in / Create account");
        InvalidateRect(g_acctLabel, nullptr, TRUE);
    }
}

// ---- actions ----
// The last port is remembered so the panel reopens on the same one.
static int loadSavedPort() {
    std::ifstream f("messager_admin.cfg");
    int p = 8080;
    if (f) { f >> p; if (p < 1 || p > 65535) p = 8080; }
    return p;
}
static void saveSavedPort(int port) {
    std::ofstream f("messager_admin.cfg", std::ios::trunc);
    if (f) f << port;
}
static void doStartStop() {
    if (g_running) {
        stopServer();
    } else {
        int port = 8080;
        try { port = std::stoi(getEditText(g_portEdit)); } catch (...) {}
        if (port < 1 || port > 65535) { MessageBoxW(g_main, L"Enter a port between 1 and 65535.", L"Messager", MB_ICONWARNING); return; }
        std::string err;
        if (!startServer(port, err)) { MessageBoxW(g_main, widen(err).c_str(), L"Could not start server", MB_ICONERROR); return; }
        { std::lock_guard<std::mutex> lk(g_ipMutex); g_publicIP.clear(); }
        fetchPublicIP();
        saveSavedPort(port);
    }
    updateServerUI();
}
// Apply the port in the box: (re)start the server on it, restarting if needed.
static void doApplyPort() {
    int port = 0;
    try { port = std::stoi(getEditText(g_portEdit)); } catch (...) {}
    if (port < 1 || port > 65535) {
        MessageBoxW(g_main, L"Enter a port between 1 and 65535.", L"Messager", MB_ICONWARNING); return;
    }
    if (g_running && port == g_port) return;   // already serving on this port
    if (g_running) stopServer();
    std::string err;
    if (!startServer(port, err)) {
        MessageBoxW(g_main, widen(err).c_str(), L"Could not start server", MB_ICONERROR);
        updateServerUI(); return;
    }
    { std::lock_guard<std::mutex> lk(g_ipMutex); g_publicIP.clear(); }
    fetchPublicIP();
    saveSavedPort(port);
    logLine("Server now listening on port " + std::to_string(port));
    updateServerUI();
}
static void openAccountWindow();   // fwd decl

// Ensure we have a valid signed-in account before posting. Returns false and
// nudges the user to the account window if not.
static bool requireAccount() {
    if (!g_account.empty() && coreUserExists(g_account)) return true;
    if (!g_account.empty() && !coreUserExists(g_account)) g_account.clear(); // account was deleted
    MessageBoxW(g_main, L"Sign in to an account before posting.\n\nUse the Account button to sign in or create one.",
                L"Account required", MB_ICONINFORMATION);
    openAccountWindow();
    return false;
}
static void doNewThread() {
    std::string title = trimStr(getEditText(g_newTitle));
    if (title.empty()) return;
    if (!requireAccount()) return;
    long long id = coreCreateThread(title, g_account);
    logLine(g_account + " created thread: " + title);
    SetWindowTextW(g_newTitle, L"");
    refreshThreads();
    g_curThread = id;
    lvSelectByParam(g_threadsLV, id);
    refreshMessages(true);
}
static void doPost() {
    if (g_curThread < 0) { MessageBoxW(g_main, L"Select a thread first.", L"Messager", MB_ICONINFORMATION); return; }
    std::string content = trimStr(getEditText(g_input));
    if (content.empty()) return;
    if (!requireAccount()) return;
    corePostMessage(g_curThread, g_account, content);
    SetWindowTextW(g_input, L"");
    refreshMessages(true);
}
static void doCopyURL() {
    if (g_connectURL.empty() || !OpenClipboard(g_main)) return;
    EmptyClipboard();
    std::wstring w = widen(g_connectURL);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (h) { memcpy(GlobalLock(h), w.c_str(), (w.size() + 1) * sizeof(wchar_t)); GlobalUnlock(h);
        SetClipboardData(CF_UNICODETEXT, h); }
    CloseClipboard();
}
static void doOpenBrowser() {
    int port = g_running ? g_port : 8080;
    try { if (!g_running) port = std::stoi(getEditText(g_portEdit)); } catch (...) {}
    std::wstring url = L"http://127.0.0.1:" + std::to_wstring(port) + L"/";
    ShellExecuteW(g_main, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// ---- Users window ----
static void refreshUsers() {
    if (!g_usersLV) return;
    long long selIdx = ListView_GetNextItem(g_usersLV, -1, LVNI_SELECTED);
    ListView_DeleteAllItems(g_usersLV);
    auto us = listUsers();
    int row = 0;
    for (auto& u : us) {
        lvInsert(g_usersLV, row, u.name, row);
        lvSetSub(g_usersLV, row, 1, fmtTime(u.created));
        lvSetSub(g_usersLV, row, 2, u.banned ? "BANNED" : "active");
        lvSetSub(g_usersLV, row, 3, u.admin ? "admin" : "member");
        ++row;
    }
    if (selIdx >= 0 && selIdx < row)
        ListView_SetItemState(g_usersLV, selIdx, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
}
static std::string usersSelectedName() {
    int i = ListView_GetNextItem(g_usersLV, -1, LVNI_SELECTED);
    if (i < 0) return "";
    wchar_t buf[128]{}; ListView_GetItemText(g_usersLV, i, 0, buf, 128);
    return narrow(buf);
}
static LRESULT CALLBACK UsersProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_usersLV = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            10, 10, 520, 300, hwnd, (HMENU)ID_U_LV, g_hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_usersLV, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        lvAddColumn(g_usersLV, 0, L"Username", 160);
        lvAddColumn(g_usersLV, 1, L"Registered", 120);
        lvAddColumn(g_usersLV, 2, L"Status", 100);
        lvAddColumn(g_usersLV, 3, L"Role", 120);
        struct { const wchar_t* t; int id; } btns[] = {
            { L"Ban", ID_U_BAN }, { L"Unban", ID_U_UNBAN },
            { L"Make admin", ID_U_PROMOTE }, { L"Remove admin", ID_U_DEMOTE },
            { L"Delete", ID_U_DELETE }, { L"Refresh", ID_U_REFRESH } };
        SendMessageW(g_usersLV, WM_SETFONT, (WPARAM)g_font, TRUE);
        SetWindowTheme(g_usersLV, L"Explorer", nullptr);
        int x = 10;
        for (auto& b : btns) {
            HWND hb = CreateWindowW(L"BUTTON", b.t, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                x, 320, 84, 28, hwnd, (HMENU)(INT_PTR)b.id, g_hInst, nullptr);
            SendMessageW(hb, WM_SETFONT, (WPARAM)g_font, TRUE);
            x += 88;
        }
        refreshUsers();
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_U_REFRESH) { refreshUsers(); return 0; }
        std::string name = usersSelectedName();
        if (name.empty()) { MessageBoxW(hwnd, L"Select a user first.", L"Users", MB_ICONINFORMATION); return 0; }
        if (id == ID_U_BAN)      { coreSetBanned(name, true);  logLine("host banned " + name); }
        else if (id == ID_U_UNBAN)   { coreSetBanned(name, false); logLine("host unbanned " + name); }
        else if (id == ID_U_PROMOTE) { coreSetAdmin(name, true);  logLine("host promoted " + name + " to admin"); }
        else if (id == ID_U_DEMOTE)  { coreSetAdmin(name, false); logLine("host removed admin from " + name); }
        else if (id == ID_U_DELETE)  {
            std::wstring q = L"Delete account \"" + widen(name) + L"\"? This cannot be undone.";
            if (MessageBoxW(hwnd, q.c_str(), L"Delete user", MB_YESNO | MB_ICONWARNING) == IDYES) {
                coreDeleteUser(name); logLine("host deleted account " + name);
            }
        }
        refreshUsers();
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_usersWin = nullptr; g_usersLV = nullptr;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
static void openUsersWindow() {
    if (g_usersWin) { SetForegroundWindow(g_usersWin); return; }
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc{}; wc.lpfnWndProc = UsersProc; wc.hInstance = g_hInst;
        wc.lpszClassName = L"MessagerUsers"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        RegisterClassW(&wc); reg = true;
    }
    g_usersWin = CreateWindowExW(0, L"MessagerUsers", L"Messager - Users & Moderation",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 560, 400,
        g_main, nullptr, g_hInst, nullptr);
    ShowWindow(g_usersWin, SW_SHOW);
}

// ---- Account window (sign in / create account for this panel) ----
static LRESULT CALLBACK AccountProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        auto lbl = [&](const wchar_t* t, int x, int y, int w) {
            HWND h = CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE, x, y, w, 20, hwnd, nullptr, g_hInst, nullptr);
            SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE); return h;
        };
        bool signedIn = !g_account.empty();
        std::wstring intro = signedIn
            ? (L"Signed in as: " + widen(g_account))
            : std::wstring(L"Sign in to an existing account, or create a new one.");
        lbl(intro.c_str(), 16, 14, 360);

        lbl(L"Username", 16, 48, 80);
        g_acUser = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            104, 46, 250, 26, hwnd, nullptr, g_hInst, nullptr);
        lbl(L"Password", 16, 82, 80);
        g_acPass = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
            104, 80, 250, 26, hwnd, nullptr, g_hInst, nullptr);
        lbl(L"(password is optional)", 104, 110, 250);

        HWND bLogin = CreateWindowW(L"BUTTON", L"Log in", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            104, 140, 110, 30, hwnd, (HMENU)ID_AC_LOGIN, g_hInst, nullptr);
        HWND bReg = CreateWindowW(L"BUTTON", L"Create account", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            224, 140, 130, 30, hwnd, (HMENU)ID_AC_REGISTER, g_hInst, nullptr);
        HWND bOut = CreateWindowW(L"BUTTON", L"Sign out", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            16, 140, 80, 30, hwnd, (HMENU)ID_AC_LOGOUT, g_hInst, nullptr);
        EnableWindow(bOut, signedIn);

        g_acStatus = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            16, 180, 360, 40, hwnd, nullptr, g_hInst, nullptr);

        for (HWND c : { g_acUser, g_acPass, bLogin, bReg, bOut, g_acStatus })
            SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        SetFocus(g_acUser);
        return 0;
    }
    case DM_GETDEFID:
        // Lets IsDialogMessage treat "Log in" as the default button, so Enter logs in.
        return MAKELRESULT(ID_AC_LOGIN, DC_HASDEFID);
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDCANCEL) { DestroyWindow(hwnd); return 0; }  // Esc closes
        if (id == IDOK) id = ID_AC_LOGIN;                       // Enter = Log in
        if (id == ID_AC_LOGOUT) {
            if (!g_account.empty()) logLine("Console signed out of " + g_account);
            g_account.clear();
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == ID_AC_LOGIN || id == ID_AC_REGISTER) {
            std::string u = getEditText(g_acUser);
            std::string p = getEditText(g_acPass);
            std::string err;
            std::string tok = (id == ID_AC_LOGIN) ? loginUser(u, p, &err) : registerUser(u, p, &err);
            if (tok.empty()) {
                SetWindowTextW(g_acStatus, widen(err).c_str());
            } else {
                g_account = userForToken(tok);
                logoutToken(tok);  // the panel tracks identity by name; don't hold a web session
                logLine(std::string("Console ") + (id == ID_AC_LOGIN ? "signed in as " : "created & signed in as ") + g_account);
                DestroyWindow(hwnd);
            }
            return 0;
        }
        return 0;
    }
    case WM_CLOSE:  DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_acctWin = nullptr; g_acUser = g_acPass = g_acStatus = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
static void openAccountWindow() {
    if (g_acctWin) { SetForegroundWindow(g_acctWin); return; }
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc{}; wc.lpfnWndProc = AccountProc; wc.hInstance = g_hInst;
        wc.lpszClassName = L"MessagerAccount"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        RegisterClassW(&wc); reg = true;
    }
    RECT pr; GetWindowRect(g_main, &pr);
    g_acctWin = CreateWindowExW(WS_EX_CONTROLPARENT, L"MessagerAccount", L"Messager - Account",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, pr.left + 120, pr.top + 120, 392, 270,
        g_main, nullptr, g_hInst, nullptr);
    ShowWindow(g_acctWin, SW_SHOW);
}

// ---- context (right-click) delete ----
static void showContextMenu(HWND fromLV) {
    long long id = lvSelectedParam(fromLV);
    if (id < 0) return;
    bool isThread = (fromLV == g_threadsLV);
    bool pinned = isThread ? coreThreadPinned(id) : coreMessagePinned(id);
    POINT pt; GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, IDM_PIN,
        pinned ? (isThread ? L"Unpin thread" : L"Unpin message")
               : (isThread ? L"Pin thread"   : L"Pin message"));
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_DELETE,
        isThread ? L"Delete thread (and its messages)" : L"Delete message");
    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_main, nullptr);
    DestroyMenu(m);
    if (cmd == IDM_PIN) {
        if (isThread) { coreSetThreadPinned(id, !pinned);
            logLine(std::string("host ") + (pinned ? "unpinned" : "pinned") + " thread " + std::to_string(id));
            refreshThreads(); }
        else { coreSetMessagePinned(id, !pinned);
            logLine(std::string("host ") + (pinned ? "unpinned" : "pinned") + " message " + std::to_string(id));
            refreshMessages(true); }
    } else if (cmd == IDM_DELETE) {
        if (isThread) {
            if (MessageBoxW(g_main, L"Delete this thread and all its messages?", L"Delete", MB_YESNO | MB_ICONWARNING) == IDYES) {
                coreDeleteThread(id); logLine("host deleted thread " + std::to_string(id));
                if (g_curThread == id) g_curThread = -1;
                refreshThreads(); refreshMessages(true);
            }
        } else {
            coreDeleteMessage(id); logLine("host deleted message " + std::to_string(id));
            refreshMessages(true);
        }
    }
}

// ---- layout ----
static void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom, pad = 14;

    // Row 1: server controls
    int y1 = 14, h1 = 30;
    MoveWindow(g_startBtn, pad, y1, 110, h1, TRUE);
    MoveWindow(g_lblPort, pad + 116, y1 + 6, 30, 18, TRUE);
    MoveWindow(g_portEdit, pad + 148, y1, 56, h1, TRUE);
    MoveWindow(g_applyBtn, pad + 208, y1, 62, h1, TRUE);
    MoveWindow(g_openBtn, pad + 278, y1, 138, h1, TRUE);
    MoveWindow(g_usersBtn, pad + 424, y1, 168, h1, TRUE);
    MoveWindow(g_status, pad + 600, y1 + 7, W - (pad + 600) - pad, 18, TRUE);

    // Row 2: connect URL (with header label above)
    int lblY = 54;
    MoveWindow(g_lblShare, pad, lblY, 200, 16, TRUE);
    int y2 = lblY + 18, h2 = 26;
    MoveWindow(g_urlEdit, pad, y2, W - pad - 104 - pad, h2, TRUE);
    MoveWindow(g_copyBtn, W - pad - 104, y2, 104, h2, TRUE);

    // Bottom log strip (header + control)
    int logH = 96;
    int logTop = H - pad - logH;
    MoveWindow(g_lblLog, pad, logTop - 18, 200, 16, TRUE);
    MoveWindow(g_log, pad, logTop, W - 2 * pad, logH, TRUE);

    int cTop = y2 + h2 + 14;          // below the URL row
    int headH = 18;
    int listTop = cTop + headH;
    int cBottom = logTop - 18 - pad;  // leave room for the log header
    int Lw = 270;

    // left column: header + threads + new-thread row
    int newRowH = 30;
    MoveWindow(g_lblThreads, pad, cTop, 200, 16, TRUE);
    MoveWindow(g_threadsLV, pad, listTop, Lw, (cBottom - newRowH - 6) - listTop, TRUE);
    MoveWindow(g_newTitle, pad, cBottom - newRowH, Lw - 74, newRowH, TRUE);
    MoveWindow(g_newBtn, pad + Lw - 68, cBottom - newRowH, 68, newRowH, TRUE);

    // right column: header + messages + account strip + input row
    int rx = pad + Lw + pad;
    int rw = W - rx - pad;
    int inputH = 58;
    int acctH = 28;
    int inputTop = cBottom - inputH;
    int acctTop = inputTop - acctH - 6;
    MoveWindow(g_lblMessages, rx, cTop, 200, 16, TRUE);
    MoveWindow(g_msgLV, rx, listTop, rw, (acctTop - 6) - listTop, TRUE);
    MoveWindow(g_acctLabel, rx, acctTop + 5, rw - 210, 20, TRUE);
    MoveWindow(g_acctBtn, rx + rw - 200, acctTop, 200, acctH, TRUE);
    MoveWindow(g_input, rx, inputTop, rw - 90, inputH, TRUE);
    MoveWindow(g_postBtn, rx + rw - 84, inputTop, 84, inputH, TRUE);

    // messages "Message" column fills remaining width
    int mw = rw - 110 - 130 - 6;
    if (mw < 120) mw = 120;
    ListView_SetColumnWidth(g_msgLV, 2, mw);
}

// ---- system tray (hidden icons) ----
static void addTrayIcon(HWND hwnd) {
    g_nid = {};
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"Messager - Server Control Panel");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    g_trayAdded = true;
}
static void removeTrayIcon() {
    if (g_trayAdded) { Shell_NotifyIconW(NIM_DELETE, &g_nid); g_trayAdded = false; }
}
static void setTrayTip(const std::wstring& tip) {
    if (!g_trayAdded) return;
    g_nid.uFlags = NIF_TIP;
    wcsncpy_s(g_nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}
static void showFromTray(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOW);
    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
}
static void minimizeToTray(HWND hwnd) {
    ShowWindow(hwnd, SW_HIDE);   // vanish from the taskbar, stay in the tray
    if (!g_toldAboutTray && g_trayAdded) {
        g_toldAboutTray = true;
        g_nid.uFlags = NIF_INFO;
        wcscpy_s(g_nid.szInfoTitle, L"Messager is still running");
        wcscpy_s(g_nid.szInfo, L"The server keeps running here in the hidden icons. Double-click to reopen, or right-click to quit.");
        g_nid.dwInfoFlags = NIIF_INFO;
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    }
}

// ---- main window proc ----
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = makeFont(10, FW_NORMAL);
        g_fontHdr = makeFont(8, FW_SEMIBOLD);
        g_bgBrush = CreateSolidBrush(COL_BG);

        auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
            return CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)id, g_hInst, nullptr);
        };
        g_startBtn = mk(L"BUTTON", L"Start server", BS_PUSHBUTTON, ID_STARTSTOP);
        g_lblPort  = mk(L"STATIC", L"Port", SS_RIGHT, 0);
        g_portEdit = mk(L"EDIT", L"8080", ES_NUMBER | WS_BORDER | ES_CENTER, ID_PORT);
        g_applyBtn = mk(L"BUTTON", L"Apply", BS_PUSHBUTTON, ID_APPLYPORT);
        g_openBtn  = mk(L"BUTTON", L"Open in browser", BS_PUSHBUTTON, ID_OPENBROWSER);
        g_usersBtn = mk(L"BUTTON", L"Users && moderation", BS_PUSHBUTTON, ID_USERS);
        g_status   = mk(L"STATIC", L"STOPPED", SS_LEFT, 0);

        g_lblShare = makeHeader(hwnd, L"SHARE THIS LINK");
        g_urlEdit  = mk(L"EDIT", L"(server stopped)", ES_READONLY | WS_BORDER | ES_AUTOHSCROLL, ID_COPYURL + 100);
        g_copyBtn  = mk(L"BUTTON", L"Copy link", BS_PUSHBUTTON, ID_COPYURL);

        g_lblThreads = makeHeader(hwnd, L"THREADS");
        g_threadsLV = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 10, 10, hwnd, (HMENU)ID_THREADS, g_hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_threadsLV, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_threadsLV, L"Explorer", nullptr);
        lvAddColumn(g_threadsLV, 0, L"Thread", 170);
        lvAddColumn(g_threadsLV, 1, L"By", 90);

        g_newTitle = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, ID_NEWTITLE);
        SendMessageW(g_newTitle, EM_SETCUEBANNER, TRUE, (LPARAM)L"New thread title...");
        g_newBtn   = mk(L"BUTTON", L"Create", BS_PUSHBUTTON, ID_NEWTHREAD);

        g_lblMessages = makeHeader(hwnd, L"MESSAGES");
        g_msgLV = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0, 0, 10, 10, hwnd, (HMENU)ID_MESSAGES, g_hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_msgLV, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_msgLV, L"Explorer", nullptr);
        lvAddColumn(g_msgLV, 0, L"Time", 110);
        lvAddColumn(g_msgLV, 1, L"Author", 130);
        lvAddColumn(g_msgLV, 2, L"Message", 400);

        g_acctLabel = mk(L"STATIC", L"Not signed in - you must sign in to post.", SS_LEFT, 0);
        g_acctBtn   = mk(L"BUTTON", L"Sign in / Create account", BS_PUSHBUTTON, ID_ACCOUNT);

        g_input   = mk(L"EDIT", L"", WS_BORDER | ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL, ID_INPUT);
        SendMessageW(g_input, EM_SETCUEBANNER, TRUE, (LPARAM)L"Write a message or paste a link...");
        g_postBtn = mk(L"BUTTON", L"Post", BS_PUSHBUTTON, ID_POST);

        g_lblLog = makeHeader(hwnd, L"SERVER ACTIVITY");
        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            0, 0, 10, 10, hwnd, (HMENU)ID_LOG, g_hInst, nullptr);

        for (HWND c : { g_startBtn, g_lblPort, g_portEdit, g_applyBtn, g_openBtn, g_usersBtn, g_status, g_urlEdit,
                        g_copyBtn, g_threadsLV, g_newTitle, g_newBtn, g_msgLV, g_acctLabel, g_acctBtn,
                        g_input, g_postBtn, g_log })
            SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);

        SetTimer(hwnd, ID_TIMER, 800, nullptr);

        addTrayIcon(hwnd);

        // Auto-start on the last-used port (remembered between runs).
        {
            int port = loadSavedPort();
            SetWindowTextW(g_portEdit, std::to_wstring(port).c_str());
            std::string err;
            if (startServer(port, err)) { fetchPublicIP(); saveSavedPort(port); }
            else appendLog("Auto-start failed (" + err + "). Change the port and click Start.");
        }
        updateServerUI();
        return 0;
    }
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = 940; mmi->ptMinTrackSize.y = 600;
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_MINIMIZE) { minimizeToTray(hwnd); return 0; }
        break;  // other system commands fall through to DefWindowProc
    case WM_TRAYICON:
        switch (LOWORD(lp)) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
            showFromTray(hwnd);
            break;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU: {
            POINT pt; GetCursorPos(&pt);
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, IDM_TRAY_SHOW, L"Open Messager");
            AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(m, MF_STRING, IDM_TRAY_QUIT, L"Quit");
            SetForegroundWindow(hwnd);   // so the menu closes on click-away
            int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(m);
            if (cmd == IDM_TRAY_SHOW) showFromTray(hwnd);
            else if (cmd == IDM_TRAY_QUIT) { stopServer(); DestroyWindow(hwnd); }
            break;
        }
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp; HWND ctl = (HWND)lp;
        if (ctl == g_status) {
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, g_running ? COL_RUNNING : COL_STOPPED);
            return (INT_PTR)g_bgBrush;
        }
        if (ctl == g_acctLabel) {
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, g_account.empty() ? COL_STOPPED : COL_RUNNING);
            return (INT_PTR)g_bgBrush;
        }
        if (ctl == g_urlEdit) {                       // read-only edit
            SetBkColor(dc, RGB(255, 255, 255)); SetTextColor(dc, COL_LINK);
            return (INT_PTR)GetStockObject(WHITE_BRUSH);
        }
        if (ctl == g_log) {                           // read-only edit
            SetBkColor(dc, RGB(255, 255, 255)); SetTextColor(dc, COL_TEXT);
            return (INT_PTR)GetStockObject(WHITE_BRUSH);
        }
        SetBkMode(dc, TRANSPARENT);
        bool isHeader = std::find(g_headerLabels.begin(), g_headerLabels.end(), ctl) != g_headerLabels.end();
        SetTextColor(dc, isHeader ? COL_HEADER : COL_TEXT);
        return (INT_PTR)g_bgBrush;
    }
    case WM_TIMER:
        if (wp == ID_TIMER) {
            for (auto& l : drainLog()) appendLog(l);
            refreshThreads();
            refreshMessages();
            updateServerUI();
        }
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wp);
        switch (id) {
        case ID_STARTSTOP:   doStartStop(); break;
        case ID_APPLYPORT:   doApplyPort(); break;
        case ID_NEWTHREAD:   doNewThread(); break;
        case ID_POST:        doPost(); break;
        case ID_COPYURL:     doCopyURL(); break;
        case ID_OPENBROWSER: doOpenBrowser(); break;
        case ID_USERS:       openUsersWindow(); break;
        case ID_ACCOUNT:     openAccountWindow(); break;
        }
        return 0;
    }
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == ID_THREADS) {
            if (nh->code == LVN_ITEMCHANGED) {
                auto* nv = (LPNMLISTVIEW)lp;
                if ((nv->uChanged & LVIF_STATE) && (nv->uNewState & LVIS_SELECTED)) {
                    g_curThread = lvSelectedParam(g_threadsLV);
                    refreshMessages(true);
                }
            } else if (nh->code == NM_RCLICK) {
                showContextMenu(g_threadsLV);
            }
        } else if (nh->idFrom == ID_MESSAGES && nh->code == NM_RCLICK) {
            showContextMenu(g_msgLV);
        }
        return 0;
    }
    case WM_CLOSE:
        if (g_running) {
            if (MessageBoxW(hwnd, L"The server is running. Stop it and quit?", L"Messager",
                MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
        }
        stopServer();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        removeTrayIcon();
        KillTimer(hwnd, ID_TIMER);
        if (g_font) DeleteObject(g_font);
        if (g_fontHdr) DeleteObject(g_fontHdr);
        if (g_bgBrush) DeleteObject(g_bgBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInst = hInst;
    loadAll();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"MessagerAdmin";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COL_BG);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassW(&wc);

    g_main = CreateWindowExW(0, L"MessagerAdmin", L"Messager - Server Control Panel",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1080, 680,
        nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_main, nCmdShow);
    UpdateWindow(g_main);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        // Enter in the port box applies the new port.
        if (msg.hwnd == g_portEdit && msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            doApplyPort(); continue;
        }
        // Account window: Enter = Log in, Esc = close (works regardless of which field has focus).
        if (g_acctWin && (msg.hwnd == g_acctWin || IsChild(g_acctWin, msg.hwnd)) && msg.message == WM_KEYDOWN) {
            if (msg.wParam == VK_RETURN) { SendMessageW(g_acctWin, WM_COMMAND, ID_AC_LOGIN, 0); continue; }
            if (msg.wParam == VK_ESCAPE) { DestroyWindow(g_acctWin); continue; }
        }
        if (g_acctWin && IsDialogMessageW(g_acctWin, &msg)) continue;
        if (g_usersWin && IsDialogMessageW(g_usersWin, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
