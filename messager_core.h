// messager_core.h - shared server core for Messager.
// Contains: data model, persistence, password hashing (Windows CNG),
// the HTTP server (start/stop), the embedded web UI, and admin/moderation
// operations. Included by both the console server (server.cpp) and the
// desktop admin app (admin.cpp).
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00  // Windows 10+ (BCryptDeriveKeyPBKDF2 needs Win7+)
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <netfw.h>    // Windows Firewall API (best-effort inbound rule)

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ===========================================================================
// Data model
// ===========================================================================
struct Thread  { long long id; std::string title; std::string author; long long created; bool pinned; };
struct Message { long long id; long long threadId; std::string author; std::string content; long long created; bool pinned; };
struct User    { std::string name; std::string saltHex; std::string hashHex; long long iterations; long long created; bool banned; bool admin; };
struct UserInfo{ std::string name; long long created; bool banned; bool admin; };

inline std::mutex g_dataMutex;
inline std::vector<Thread>  g_threads;
inline std::vector<Message> g_messages;
inline long long g_nextThreadId  = 1;
inline long long g_nextMessageId = 1;

inline std::mutex g_authMutex;
inline std::unordered_map<std::string, User> g_users;           // lowercase name -> user
inline std::unordered_map<std::string, std::string> g_sessions; // token -> username
inline std::unordered_map<std::string, long long> g_sessionSeen; // token -> last-seen epoch

// presence: a session counts as "online" if seen within this window; it is
// dropped entirely after the TTL.
inline const long long kOnlineWindow = 30;   // seconds
inline const long long kSessionTTL   = 120;  // seconds

inline const std::string kDataFile  = "messager_data.txt";
inline const std::string kUsersFile = "messager_users.txt";
inline const long long   kPbkdf2Iterations = 120000;

// server lifecycle
inline std::atomic<bool> g_running{false};
inline SOCKET   g_listener = INVALID_SOCKET;
inline int      g_port = 0;
inline std::thread g_acceptThread;
inline bool     g_wsaInit = false;

// log buffer (drained by the GUI / printed by console)
inline std::mutex g_logMutex;
inline std::vector<std::string> g_logBuf;

// ===========================================================================
// Small helpers
// ===========================================================================
inline std::string nowStamp() {
    time_t t = time(nullptr); struct tm tmv; localtime_s(&tmv, &t);
    char b[16]; snprintf(b, sizeof(b), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return b;
}
inline void logLine(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    g_logBuf.push_back(nowStamp() + "  " + s);
}
inline std::vector<std::string> drainLog() {
    std::lock_guard<std::mutex> lk(g_logMutex);
    std::vector<std::string> out; out.swap(g_logBuf); return out;
}
inline std::string ipStr(const sockaddr_in& a) {   // dotted-quad of a peer, for activity logs
    unsigned long v = ntohl(a.sin_addr.s_addr); char b[32];
    snprintf(b, sizeof(b), "%lu.%lu.%lu.%lu", (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
    return b;
}

inline std::string escapeField(const std::string& s) {
    std::string o; o.reserve(s.size()+8);
    for (char c : s) switch (c) {
        case '\\': o += "\\\\"; break; case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break; case '\t': o += "\\t"; break;
        default: o += c;
    }
    return o;
}
inline std::string unescapeField(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i+1 < s.size()) { char n = s[++i];
            switch (n) { case 'n': o+='\n'; break; case 'r': o+='\r'; break;
                         case 't': o+='\t'; break; case '\\': o+='\\'; break; default: o+=n; }
        } else o += s[i];
    }
    return o;
}
inline std::vector<std::string> splitTabs(const std::string& line) {
    std::vector<std::string> p; std::string cur;
    for (char c : line) { if (c=='\t'){ p.push_back(cur); cur.clear(); } else cur += c; }
    p.push_back(cur); return p;
}
inline std::string jsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size()+8);
    for (unsigned char c : s) switch (c) {
        case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break; case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break; case '\b': o += "\\b"; break; case '\f': o += "\\f"; break;
        default: if (c < 0x20) { char b[8]; snprintf(b,sizeof(b),"\\u%04x",c); o += b; } else o += (char)c;
    }
    return o;
}
inline std::string urlDecode(const std::string& s) {
    std::string o; o.reserve(s.size());
    auto hex = [](char h)->int{ if(h>='0'&&h<='9')return h-'0'; if(h>='a'&&h<='f')return h-'a'+10;
                                if(h>='A'&&h<='F')return h-'A'+10; return -1; };
    for (size_t i=0;i<s.size();++i){ char c=s[i];
        if(c=='+') o+=' ';
        else if(c=='%'&&i+2<s.size()){ int hi=hex(s[i+1]),lo=hex(s[i+2]);
            if(hi>=0&&lo>=0){ o+=(char)((hi<<4)|lo); i+=2; } else o+=c; }
        else o+=c;
    }
    return o;
}
inline std::string trimStr(const std::string& s) {
    size_t a=s.find_first_not_of(" \t\r\n"); if(a==std::string::npos)return "";
    size_t b=s.find_last_not_of(" \t\r\n"); return s.substr(a,b-a+1);
}
inline std::string toLower(std::string s){ for(auto&c:s)c=(char)tolower((unsigned char)c); return s; }
inline std::unordered_map<std::string,std::string> parseForm(const std::string& body){
    std::unordered_map<std::string,std::string> m; size_t i=0;
    while(i<body.size()){ size_t amp=body.find('&',i); if(amp==std::string::npos)amp=body.size();
        std::string pair=body.substr(i,amp-i); size_t eq=pair.find('=');
        if(eq!=std::string::npos) m[urlDecode(pair.substr(0,eq))]=urlDecode(pair.substr(eq+1));
        i=amp+1;
    }
    return m;
}

// ===========================================================================
// Crypto (Windows CNG)
// ===========================================================================
inline std::string toHex(const unsigned char* p, size_t n){
    static const char* d="0123456789abcdef"; std::string o; o.reserve(n*2);
    for(size_t i=0;i<n;++i){ o+=d[p[i]>>4]; o+=d[p[i]&0xF]; } return o;
}
inline std::vector<unsigned char> randomBytes(size_t n){
    std::vector<unsigned char> v(n);
    BCryptGenRandom(nullptr, v.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return v;
}
inline std::string pbkdf2Hex(const std::string& pw, const std::vector<unsigned char>& salt,
                             long long iters, size_t dkLen=32){
    BCRYPT_ALG_HANDLE h=nullptr;
    if(BCryptOpenAlgorithmProvider(&h,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG)!=0) return "";
    std::vector<unsigned char> out(dkLen);
    NTSTATUS st=BCryptDeriveKeyPBKDF2(h,(PUCHAR)pw.data(),(ULONG)pw.size(),
        (PUCHAR)salt.data(),(ULONG)salt.size(),(ULONGLONG)iters,out.data(),(ULONG)out.size(),0);
    BCryptCloseAlgorithmProvider(h,0);
    if(st!=0) return "";
    return toHex(out.data(),out.size());
}
inline bool ctEqual(const std::string& a,const std::string& b){
    if(a.size()!=b.size())return false; unsigned char d=0;
    for(size_t i=0;i<a.size();++i) d|=(unsigned char)(a[i]^b[i]); return d==0;
}
inline std::string newSessionToken(){ auto r=randomBytes(32); return toHex(r.data(),r.size()); }

// ===========================================================================
// Persistence
// ===========================================================================
inline void saveData(){ // caller holds g_dataMutex
    std::ofstream f(kDataFile, std::ios::binary|std::ios::trunc); if(!f)return;
    for(const auto&t:g_threads)
        f<<"T\t"<<t.id<<'\t'<<escapeField(t.title)<<'\t'<<escapeField(t.author)<<'\t'<<t.created
         <<'\t'<<(t.pinned?1:0)<<'\n';
    for(const auto&m:g_messages)
        f<<"M\t"<<m.id<<'\t'<<m.threadId<<'\t'<<escapeField(m.author)<<'\t'<<m.created<<'\t'
         <<escapeField(m.content)<<'\t'<<(m.pinned?1:0)<<'\n';
}
inline void loadData(){
    std::ifstream f(kDataFile, std::ios::binary); if(!f)return; std::string line;
    while(std::getline(f,line)){ if(!line.empty()&&line.back()=='\r')line.pop_back(); if(line.empty())continue;
        auto p=splitTabs(line); if(p.empty())continue;
        if(p[0]=="T"&&p.size()>=5){ Thread t; t.id=std::stoll(p[1]); t.title=unescapeField(p[2]);
            t.author=unescapeField(p[3]); t.created=std::stoll(p[4]);
            t.pinned=(p.size()>=6 && p[5]=="1"); g_threads.push_back(t);
            if(t.id>=g_nextThreadId)g_nextThreadId=t.id+1;
        } else if(p[0]=="M"&&p.size()>=6){ Message m; m.id=std::stoll(p[1]); m.threadId=std::stoll(p[2]);
            m.author=unescapeField(p[3]); m.created=std::stoll(p[4]); m.content=unescapeField(p[5]);
            m.pinned=(p.size()>=7 && p[6]=="1");
            g_messages.push_back(m); if(m.id>=g_nextMessageId)g_nextMessageId=m.id+1;
        }
    }
}
inline void saveUsers(){ // caller holds g_authMutex
    std::ofstream f(kUsersFile, std::ios::binary|std::ios::trunc); if(!f)return;
    for(const auto&kv:g_users){ const User&u=kv.second;
        f<<"U\t"<<escapeField(u.name)<<'\t'<<u.saltHex<<'\t'<<u.hashHex<<'\t'<<u.iterations<<'\t'
         <<u.created<<'\t'<<(u.banned?1:0)<<'\t'<<(u.admin?1:0)<<'\n';
    }
}
inline void loadUsers(){
    std::ifstream f(kUsersFile, std::ios::binary); if(!f)return; std::string line;
    while(std::getline(f,line)){ if(!line.empty()&&line.back()=='\r')line.pop_back(); if(line.empty())continue;
        auto p=splitTabs(line);
        if(p.size()>=6&&p[0]=="U"){ User u; u.name=unescapeField(p[1]); u.saltHex=p[2]; u.hashHex=p[3];
            u.iterations=std::stoll(p[4]); u.created=std::stoll(p[5]);
            u.banned = (p.size()>=7 && p[6]=="1");
            u.admin  = (p.size()>=8 && p[7]=="1");
            g_users[toLower(u.name)]=u;
        }
    }
}
inline void loadAll(){ loadUsers(); loadData(); }

// ===========================================================================
// Data operations (used by both HTTP handlers and the GUI)
// ===========================================================================
// Pinned items first, preserving relative order within each group.
inline void pinnedFirst(std::vector<Thread>& v){ std::stable_partition(v.begin(),v.end(),[](const Thread& t){return t.pinned;}); }
inline void pinnedFirst(std::vector<Message>& v){ std::stable_partition(v.begin(),v.end(),[](const Message& m){return m.pinned;}); }

inline std::vector<Thread>  listThreads(){ std::lock_guard<std::mutex> lk(g_dataMutex);
    std::vector<Thread> v=g_threads; pinnedFirst(v); return v; }
inline std::vector<Message> listMessages(long long tid){ std::lock_guard<std::mutex> lk(g_dataMutex);
    std::vector<Message> out; for(auto&m:g_messages) if(m.threadId==tid) out.push_back(m); pinnedFirst(out); return out; }
inline std::vector<UserInfo> listUsers(){ std::lock_guard<std::mutex> lk(g_authMutex);
    std::vector<UserInfo> v; for(auto&kv:g_users) v.push_back({kv.second.name,kv.second.created,kv.second.banned,kv.second.admin});
    std::sort(v.begin(),v.end(),[](const UserInfo&a,const UserInfo&b){ return a.created<b.created; }); return v; }
inline int userCount(){ std::lock_guard<std::mutex> lk(g_authMutex); return (int)g_users.size(); }
inline int activeSessions(){ std::lock_guard<std::mutex> lk(g_authMutex); return (int)g_sessions.size(); }

inline bool coreThreadExists(long long id){ std::lock_guard<std::mutex> lk(g_dataMutex);
    for(auto&t:g_threads) if(t.id==id) return true; return false; }

inline long long coreCreateThread(const std::string& title,const std::string& author){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    Thread t; t.id=g_nextThreadId++; t.title=title; t.author=author; t.created=(long long)time(nullptr); t.pinned=false;
    g_threads.push_back(t); saveData(); return t.id;
}
inline long long corePostMessage(long long tid,const std::string& author,const std::string& content){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    Message m; m.id=g_nextMessageId++; m.threadId=tid; m.author=author; m.content=content; m.created=(long long)time(nullptr); m.pinned=false;
    g_messages.push_back(m); saveData(); return m.id;
}
inline bool coreSetThreadPinned(long long id,bool pinned){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    for(auto&t:g_threads) if(t.id==id){ t.pinned=pinned; saveData(); return true; } return false;
}
inline bool coreSetMessagePinned(long long id,bool pinned){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    for(auto&m:g_messages) if(m.id==id){ m.pinned=pinned; saveData(); return true; } return false;
}
inline bool coreThreadPinned(long long id){ std::lock_guard<std::mutex> lk(g_dataMutex);
    for(auto&t:g_threads) if(t.id==id) return t.pinned; return false; }
inline bool coreMessagePinned(long long id){ std::lock_guard<std::mutex> lk(g_dataMutex);
    for(auto&m:g_messages) if(m.id==id) return m.pinned; return false; }
inline bool coreDeleteThread(long long id){
    std::lock_guard<std::mutex> lk(g_dataMutex); bool found=false;
    for(size_t i=0;i<g_threads.size();++i) if(g_threads[i].id==id){ g_threads.erase(g_threads.begin()+i); found=true; break; }
    g_messages.erase(std::remove_if(g_messages.begin(),g_messages.end(),
        [&](const Message&m){ return m.threadId==id; }), g_messages.end());
    if(found) saveData(); return found;
}
inline bool coreDeleteMessage(long long id){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    size_t before=g_messages.size();
    g_messages.erase(std::remove_if(g_messages.begin(),g_messages.end(),
        [&](const Message&m){ return m.id==id; }), g_messages.end());
    bool changed = g_messages.size()!=before; if(changed) saveData(); return changed;
}

inline bool coreUserExists(const std::string& name){ std::lock_guard<std::mutex> lk(g_authMutex);
    return g_users.count(toLower(trimStr(name))) > 0; }
inline bool isAdminUser(const std::string& name){ std::lock_guard<std::mutex> lk(g_authMutex);
    auto it=g_users.find(toLower(name)); return it!=g_users.end() && it->second.admin; }
inline bool isBannedUser(const std::string& name){ std::lock_guard<std::mutex> lk(g_authMutex);
    auto it=g_users.find(toLower(name)); return it!=g_users.end() && it->second.banned; }

inline void dropSessionsFor(const std::string& name){ // caller holds g_authMutex
    for(auto it=g_sessions.begin(); it!=g_sessions.end(); ){
        if(toLower(it->second)==toLower(name)){ g_sessionSeen.erase(it->first); it=g_sessions.erase(it); }
        else ++it;
    }
}
// Mark a session as active right now.
inline void touchSession(const std::string& token){
    if(token.empty())return; std::lock_guard<std::mutex> lk(g_authMutex);
    if(g_sessions.count(token)) g_sessionSeen[token]=(long long)time(nullptr);
}
// Distinct accounts seen within the online window; drops sessions past the TTL.
inline int onlineCount(){
    std::lock_guard<std::mutex> lk(g_authMutex);
    long long now=(long long)time(nullptr);
    for(auto it=g_sessions.begin(); it!=g_sessions.end(); ){
        auto s=g_sessionSeen.find(it->first);
        long long seen = s==g_sessionSeen.end()? 0 : s->second;
        if(now-seen>kSessionTTL){ g_sessionSeen.erase(it->first); it=g_sessions.erase(it); }
        else ++it;
    }
    std::unordered_set<std::string> people;
    for(auto&kv:g_sessions){ auto s=g_sessionSeen.find(kv.first);
        long long seen = s==g_sessionSeen.end()? 0 : s->second;
        if(now-seen<=kOnlineWindow) people.insert(toLower(kv.second));
    }
    return (int)people.size();
}
inline bool coreSetBanned(const std::string& name,bool banned){
    std::lock_guard<std::mutex> lk(g_authMutex); auto it=g_users.find(toLower(name));
    if(it==g_users.end())return false; it->second.banned=banned; if(banned) dropSessionsFor(name);
    saveUsers(); return true;
}
inline bool coreSetAdmin(const std::string& name,bool admin){
    std::lock_guard<std::mutex> lk(g_authMutex); auto it=g_users.find(toLower(name));
    if(it==g_users.end())return false; it->second.admin=admin; saveUsers(); return true;
}
inline bool coreDeleteUser(const std::string& name){
    std::lock_guard<std::mutex> lk(g_authMutex); auto it=g_users.find(toLower(name));
    if(it==g_users.end())return false; dropSessionsFor(name); g_users.erase(it); saveUsers(); return true;
}

// ---- account auth ----
inline std::string userForToken(const std::string& token){
    if(token.empty())return ""; std::lock_guard<std::mutex> lk(g_authMutex);
    auto it=g_sessions.find(token); return it==g_sessions.end()? "": it->second;
}
inline std::string registerUser(const std::string& name,const std::string& password,std::string* err){
    std::string t=trimStr(name);
    if(t.size()<2||t.size()>40){ *err="Username must be 2-40 characters."; return ""; }
    for(char c:t) if(c=='\t'||c=='\n'||c=='\r'){ *err="Invalid username."; return ""; }
    // Password may be empty (accounts with no password are allowed).
    std::lock_guard<std::mutex> lk(g_authMutex);
    if(g_users.count(toLower(t))){ *err="That username is taken."; return ""; }
    bool firstUser = g_users.empty();
    auto salt=randomBytes(16); User u; u.name=t; u.saltHex=toHex(salt.data(),salt.size());
    u.hashHex=pbkdf2Hex(password,salt,kPbkdf2Iterations); u.iterations=kPbkdf2Iterations;
    u.created=(long long)time(nullptr); u.banned=false; u.admin=firstUser;
    if(u.hashHex.empty()){ *err="Server crypto error."; return ""; }
    g_users[toLower(t)]=u; saveUsers();
    std::string tok=newSessionToken(); g_sessions[tok]=u.name; g_sessionSeen[tok]=(long long)time(nullptr);
    logLine(std::string("New account registered: ")+u.name+(firstUser?" (admin)":""));
    return tok;
}
inline std::string loginUser(const std::string& name,const std::string& password,std::string* err){
    std::lock_guard<std::mutex> lk(g_authMutex);
    auto it=g_users.find(toLower(trimStr(name)));
    if(it==g_users.end()){ *err="Invalid username or password."; return ""; }
    User& u=it->second;
    if(u.banned){ *err="This account has been banned."; return ""; }
    std::vector<unsigned char> salt;
    for(size_t i=0;i+1<u.saltHex.size(); i+=2) salt.push_back((unsigned char)std::stoi(u.saltHex.substr(i,2),nullptr,16));
    std::string cand=pbkdf2Hex(password,salt,u.iterations);
    if(cand.empty()||!ctEqual(cand,u.hashHex)){ *err="Invalid username or password."; return ""; }
    std::string tok=newSessionToken(); g_sessions[tok]=u.name; g_sessionSeen[tok]=(long long)time(nullptr);
    logLine(std::string("Login: ")+u.name);
    return tok;
}
inline void logoutToken(const std::string& token){ if(token.empty())return;
    std::lock_guard<std::mutex> lk(g_authMutex); g_sessions.erase(token); g_sessionSeen.erase(token); }

// ===========================================================================
// JSON builders for the API
// ===========================================================================
inline std::string threadsJson(){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    std::vector<Thread> v=g_threads; pinnedFirst(v);
    std::ostringstream o; o<<"[";
    for(size_t i=0;i<v.size();++i){ const auto&t=v[i]; if(i)o<<",";
        o<<"{\"id\":"<<t.id<<",\"title\":\""<<jsonEscape(t.title)<<"\",\"author\":\""<<jsonEscape(t.author)
         <<"\",\"created\":"<<t.created<<",\"pinned\":"<<(t.pinned?"true":"false")<<"}"; }
    o<<"]"; return o.str();
}
inline std::string messagesJson(long long tid){
    std::lock_guard<std::mutex> lk(g_dataMutex);
    std::vector<Message> v; for(const auto&m:g_messages) if(m.threadId==tid) v.push_back(m); pinnedFirst(v);
    std::ostringstream o; o<<"["; bool first=true;
    for(const auto&m:v){ if(!first)o<<","; first=false;
        o<<"{\"id\":"<<m.id<<",\"author\":\""<<jsonEscape(m.author)<<"\",\"content\":\""<<jsonEscape(m.content)
         <<"\",\"created\":"<<m.created<<",\"pinned\":"<<(m.pinned?"true":"false")<<"}"; }
    o<<"]"; return o.str();
}

// ===========================================================================
// The web UI
// ===========================================================================
inline const char* PAGE_HTML = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Messager</title>
<style>
  :root{
    --bg:#f6f7f9; --panel:#ffffff; --border:#e2e4e8; --border2:#eef0f2;
    --text:#1c1e21; --muted:#6b7280; --input-bg:#ffffff; --input-border:#cfd3d9;
    --hover:#f2f4f7; --active:#e3effb; --msg-bg:#fbfcfd; --msg-border:#e6e8eb;
    --link:#2563eb; --primary:#2c4b86; --primary-hover:#253e6f; --badge:#2563eb;
    --pinned-bg:#fff8e6; --pin-accent:#f59e0b; --danger:#dc2626;
  }
  :root[data-theme="dark"]{
    --bg:#16181c; --panel:#1e2126; --border:#2c2f36; --border2:#2c2f36;
    --text:#e7e9ea; --muted:#8b929c; --input-bg:#2a2d33; --input-border:#3a3d44;
    --hover:#262a30; --active:#2d4a63; --msg-bg:#24272d; --msg-border:#2c2f36;
    --link:#6ea8ff; --primary:#4b5563; --primary-hover:#3a424d; --badge:#3b82f6;
    --pinned-bg:#2c2a1e; --pin-accent:#eab308; --danger:#f87171;
  }
  @media (prefers-color-scheme:dark){
    :root:not([data-theme="light"]){
      --bg:#16181c; --panel:#1e2126; --border:#2c2f36; --border2:#2c2f36;
      --text:#e7e9ea; --muted:#8b929c; --input-bg:#2a2d33; --input-border:#3a3d44;
      --hover:#262a30; --active:#2d4a63; --msg-bg:#24272d; --msg-border:#2c2f36;
      --link:#6ea8ff; --primary:#4b5563; --primary-hover:#3a424d; --badge:#3b82f6;
      --pinned-bg:#2c2a1e; --pin-accent:#eab308; --danger:#f87171;
    }
  }
  *{box-sizing:border-box;}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);}
  #app{display:flex;flex-direction:column;height:100vh;}
  #content{display:grid;grid-template-columns:1fr 300px;flex:1;overflow:hidden;}
  aside{border-left:1px solid var(--border);background:var(--panel);display:flex;flex-direction:column;overflow:hidden;}
  main{display:flex;flex-direction:column;overflow:hidden;background:var(--panel);}
  header{padding:12px 16px;border-bottom:1px solid var(--border);background:var(--panel);display:flex;align-items:center;gap:10px;flex-shrink:0;}
  h2{font-size:16px;margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .threadtitlebar{text-align:center;flex-shrink:0;}
  .threadtitlebar h2{padding:10px 16px;}
  .threadtitlebar h2:empty{display:none;}
  .brand{font-weight:700;padding:14px 16px;font-size:17px;border-bottom:1px solid var(--border);cursor:pointer;}
  .brand small{font-weight:400;}
  .newthread{padding:12px;border-top:1px solid var(--border);display:flex;gap:6px;}
  .threads{overflow-y:auto;flex:1;}
  .thread{padding:11px 14px;border-bottom:1px solid var(--border2);cursor:pointer;}
  .thread:hover{background:var(--hover);} .thread.active{background:var(--active);}
  .thread.pinned{box-shadow:inset 3px 0 0 var(--pin-accent);}
  .thread .title{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .muted{color:var(--muted);font-size:12px;}
  .messages{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px;}
  .msg{border:1px solid var(--msg-border);background:var(--msg-bg);border-radius:10px;padding:10px 12px;}
  .msg.pinned{background:var(--pinned-bg);box-shadow:inset 3px 0 0 var(--pin-accent);}
  .msg .meta{font-size:12px;margin-bottom:3px;display:flex;align-items:center;gap:6px;} .msg .meta b{color:var(--link);}
  .msg .body{white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere;} .msg a{color:var(--link);}
  .composer{border-top:1px solid var(--border);padding:12px 16px;display:flex;flex-direction:column;gap:8px;flex-shrink:0;}
  .row{display:flex;gap:8px;align-items:center;}
  input,textarea{font:inherit;padding:8px 10px;border:1px solid var(--input-border);border-radius:8px;background:var(--input-bg);color:var(--text);width:100%;}
  textarea{resize:vertical;min-height:46px;}
  button{font:inherit;font-weight:600;padding:8px 14px;border:0;border-radius:8px;background:var(--primary);color:#fff;cursor:pointer;white-space:nowrap;}
  button:hover{background:var(--primary-hover);}
  button.link{background:none;color:var(--link);padding:4px;font-weight:600;}
  button.ghost{background:transparent;color:var(--muted);border:1px solid var(--input-border);}
  button.ghost:hover{background:var(--hover);}
  button.themebtn{background:none;border:0;padding:3px;color:#9199a3;cursor:pointer;display:inline-flex;align-items:center;border-radius:6px;}
  button.themebtn:hover{background:var(--hover);color:#9199a3;}
  button.themebtn svg{width:18px;height:18px;display:block;}
  .rowbtns{margin-left:auto;display:inline-flex;gap:2px;align-items:center;}
  .iconbtn{background:none;border:0;cursor:pointer;padding:2px 5px;line-height:1;color:var(--muted);display:inline-flex;align-items:center;border-radius:6px;}
  .iconbtn:hover{background:var(--hover);color:var(--text);}
  .iconbtn.on{color:var(--pin-accent);}
  .iconbtn.del:hover{color:var(--danger);}
  .iconbtn svg{width:15px;height:15px;display:block;}
  .thread .title .rowbtns{float:right;}
  .pin{color:var(--pin-accent);}
  .pin svg{width:13px;height:13px;vertical-align:-2px;}
  .badge{background:var(--badge);color:#fff;font-size:11px;font-weight:700;padding:1px 7px;border-radius:6px;letter-spacing:.3px;}
  .empty{margin:auto;text-align:center;color:var(--muted);padding:40px;}
  #auth{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.45);z-index:10;}
  .card{position:relative;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:26px;width:340px;max-width:92vw;box-shadow:0 10px 30px rgba(0,0,0,.25);}
  .authclose{position:absolute;top:10px;right:10px;background:none;border:0;color:var(--muted);font-size:20px;line-height:1;padding:4px 8px;cursor:pointer;}
  .authclose:hover{color:var(--text);background:none;}
  .card h1{font-size:20px;margin:0 0 4px;} .card .sub{color:var(--muted);margin:0 0 18px;font-size:13px;}
  .card label{font-size:13px;font-weight:600;display:block;margin:12px 0 4px;}
  .card button.primary{width:100%;margin-top:18px;padding:10px;}
  .err{color:var(--danger);font-size:13px;min-height:18px;margin-top:10px;} .switch{text-align:center;margin-top:14px;font-size:13px;}
</style></head><body>
  <div id="auth" style="display:none" onclick="if(event.target===this)closeAuth()"><div class="card">
    <button class="authclose" title="Close" onclick="closeAuth()">&times;</button>
    <h1 id="authTitle">Sign in to Messager</h1>
    <p class="sub" id="authSub">Sign in to post and start threads.</p>
    <label>Username</label><input id="authUser" autocomplete="username" maxlength="40">
    <label>Password <span class="muted" style="font-weight:400">(optional)</span></label><input id="authPass" type="password" autocomplete="current-password">
    <button class="primary" id="authBtn" onclick="doAuth()">Sign in</button>
    <div class="err" id="authErr"></div><div class="switch" id="authSwitch"></div>
  </div></div>
  <div id="app" style="display:none">
    <header>
      <div style="margin-left:auto" class="row">
        <span class="badge" id="adminBadge" style="display:none">ADMIN</span>
        <span class="muted" id="whoami"></span>
        <button class="themebtn" id="themeBtn" title="Toggle dark mode" onclick="toggleTheme()"></button>
        <button class="ghost" id="signBtn" onclick="openAuth()">Sign in</button>
        <button class="ghost" id="logoutBtn" style="display:none" onclick="logout()">Log out</button>
      </div>
    </header>
    <div id="content">
      <main>
        <div class="threadtitlebar"><h2 id="threadTitle"></h2></div>
        <div class="messages" id="messages"></div>
        <div class="composer" id="composer" style="display:none">
          <div class="row" id="voicebar" style="display:none;justify-content:flex-start;gap:8px;margin-bottom:6px">
            <button class="ghost" id="voiceBtn" onclick="voiceToggle()">Join voice</button>
            <button class="ghost" id="voiceMuteBtn" style="display:none" onclick="voiceMuteToggle()">Mute</button>
            <span class="muted" id="voiceMembers"></span>
            <select id="screenQuality" class="ghost" title="Quality you send"><option value="0">Low 360p</option><option value="1" selected>Balanced 720p</option><option value="2">High 1080p</option></select>
            <button class="ghost" id="screenBtn" onclick="screenToggle()">Share screen</button>
            <span class="muted" id="screenSharers"></span>
          </div>
          <textarea id="msgInput" placeholder=""></textarea>
          <div class="row" style="justify-content:flex-end"><button onclick="postMessage()">Post</button></div>
        </div>
      </main>
      <aside>
        <div class="threads" id="threadList" onclick="if(!event.target.closest('.thread'))deselectThread()"></div>
        <div class="newthread" id="newThreadWrap"><input id="newThreadTitle" placeholder="" maxlength="120"><button onclick="createThread()">+</button></div>
      </aside>
    </div>
  </div>
<script>
let me=null,isAdmin=false,currentThread=null,threads=[],authMode='login',pollTimer=null,pingTimer=null;
let voiceOn=false,voiceRoom=null,voiceMuted=false,voiceMemTimer=null;
let screenOn=false,screenShareRoom=null,screenShareQuality=1,screenViewing=null,screenViewLayers=1,screenViewLayer=0,screenStatusTimer=null,screenAnnTimer=null;
const LAYER_LABELS=['Low 360p','Medium 720p','High 1080p'];
const IN_CLIENT=!!(window.chrome&&window.chrome.webview);   // voice works only in the desktop client
const TRASH='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>';
const PIN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14l-1.6-2.6A2 2 0 0 1 17 13.3V7a2 2 0 0 0-2-2H9a2 2 0 0 0-2 2v6.3a2 2 0 0 1-.4 1.1L5 17z"/></svg>';
const MOON='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
const SUN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function linkify(s){return esc(s).replace(/(https?:\/\/[^\s<]+)/g,u=>'<a href="'+u+'" target="_blank" rel="noopener noreferrer">'+u+'</a>');}
function timeago(sec){return new Date(sec*1000).toLocaleString();}
// ---- theme ----
function effectiveTheme(){return document.documentElement.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('messager_theme',t);themeBtn.innerHTML=t==='dark'?MOON:SUN;}
function toggleTheme(){applyTheme(effectiveTheme()==='dark'?'light':'dark');}
(function(){const s=localStorage.getItem('messager_theme');if(s){document.documentElement.setAttribute('data-theme',s);}})();
// ---- auth ----
function renderAuth(){const l=authMode==='login';
  authTitle.textContent=l?'Sign in to Messager':'Create your account';
  authSub.textContent=l?'Sign in to post and start threads.':'Pick a username. A password is optional.';
  authBtn.textContent=l?'Sign in':'Create account';
  authPass.setAttribute('autocomplete',l?'current-password':'new-password');
  authSwitch.innerHTML=l?"No account? <button class='link' onclick=\"switchAuth('register')\">Register</button>":"Have an account? <button class='link' onclick=\"switchAuth('login')\">Sign in</button>";
  authErr.textContent='';}
function switchAuth(m){authMode=m;renderAuth();}
function openAuth(){authMode='login';renderAuth();auth.style.display='flex';authUser.focus();}
function closeAuth(){auth.style.display='none';authErr.textContent='';}
// Reflect logged-in vs anonymous throughout the UI.
function updateAuthUI(){const inn=!!me;
  document.body.setAttribute('data-auth',inn?'in':'out');
  whoami.textContent=inn?('@'+me):'';whoami.style.display=inn?'':'none';
  adminBadge.style.display=(inn&&isAdmin)?'inline-block':'none';
  signBtn.style.display=inn?'none':'';logoutBtn.style.display=inn?'':'none';
  newThreadWrap.style.display=inn?'flex':'none';
  composer.style.display=(inn&&currentThread!==null)?'flex':'none';
  if(!inn&&voiceOn)voiceLeave(); updateVoiceUI();}
async function doAuth(){const u=authUser.value.trim(),p=authPass.value;
  if(!u){authErr.textContent='Username required.';return;}
  const r=await fetch('/api/'+authMode,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)});
  const d=await r.json(); if(d.error){authErr.textContent=d.error;return;}
  me=d.user;isAdmin=!!d.admin;authPass.value='';closeAuth();updateAuthUI();loadThreads();loadMessages();ping();}
async function logout(){await fetch('/api/logout',{method:'POST'});me=null;isAdmin=false;
  updateAuthUI();loadThreads();loadMessages();}
function ping(){if(me)fetch('/api/ping',{method:'POST'}).catch(()=>{});}
function showApp(){app.style.display='flex';themeBtn.innerHTML=effectiveTheme()==='dark'?MOON:SUN;
  updateAuthUI();loadThreads();
  if(!pollTimer)pollTimer=setInterval(()=>{loadThreads();loadMessages();},3000);
  if(!pingTimer)pingTimer=setInterval(ping,10000); ping();}
async function api(url,opts){const r=await fetch(url,opts);
  if(r.status===401){me=null;isAdmin=false;updateAuthUI();openAuth();throw new Error('unauthorized');}return r;}
// ---- threads ----
async function loadThreads(){let r;try{r=await api('/api/threads');}catch(e){return;}threads=await r.json();
  const el=threadList; if(threads.length===0){el.innerHTML='<div class="empty">No threads yet.</div>';return;}
  el.innerHTML=threads.map(t=>{
    let btns='';
    if(isAdmin){btns='<span class="rowbtns">'
      +'<button class="iconbtn'+(t.pinned?' on':'')+'" title="'+(t.pinned?'Unpin':'Pin')+' thread" onclick="event.stopPropagation();pinThread('+t.id+','+(t.pinned?0:1)+')">'+PIN+'</button>'
      +'<button class="iconbtn del" title="Delete thread" onclick="event.stopPropagation();delThread('+t.id+')">'+TRASH+'</button></span>';}
    const pin=t.pinned?'<span class="pin">'+PIN+'</span> ':'';
    return '<div class="thread'+(t.id===currentThread?' active':'')+(t.pinned?' pinned':'')+'" onclick="openThread('+t.id+')">'
      +'<div class="title">'+pin+esc(t.title)+btns+'</div>'
      +'<div class="muted">by '+esc(t.author)+'</div></div>';}).join('');}
async function createThread(){if(!me){openAuth();return;}const inp=newThreadTitle,title=inp.value.trim();if(!title)return;let r;
  try{r=await api('/api/threads',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'title='+encodeURIComponent(title)});}catch(e){return;}
  const t=await r.json();inp.value='';await loadThreads();openThread(t.id);}
async function openThread(id){if(voiceOn&&voiceRoom!==('t'+id))voiceLeave();if(screenShareRoom&&screenShareRoom!==('t'+id+':screen'))screenStopShare();if(screenViewing)screenStopView();currentThread=id;const t=threads.find(x=>x.id===id);
  threadTitle.textContent=t?t.title:'Thread';composer.style.display=me?'flex':'none';updateVoiceUI();updateScreenUI();await loadThreads();await loadMessages();}
function deselectThread(){if(voiceOn)voiceLeave();if(screenOn)screenStopShare();if(screenViewing)screenStopView();currentThread=null;threadTitle.textContent='';composer.style.display='none';messages.innerHTML='';updateVoiceUI();updateScreenUI();loadThreads();}
// ---- messages ----
async function loadMessages(){if(currentThread===null)return;let r;
  try{r=await api('/api/messages?thread='+currentThread);}catch(e){return;}const msgs=await r.json();const el=messages;
  if(msgs.length===0){el.innerHTML='';return;}
  const atBottom=el.scrollHeight-el.scrollTop-el.clientHeight<80;
  el.innerHTML=msgs.map(m=>{
    let btns='';
    if(isAdmin){btns='<span class="rowbtns">'
      +'<button class="iconbtn'+(m.pinned?' on':'')+'" title="'+(m.pinned?'Unpin':'Pin')+' message" onclick="pinMsg('+m.id+','+(m.pinned?0:1)+')">'+PIN+'</button>'
      +'<button class="iconbtn del" title="Delete message" onclick="delMsg('+m.id+')">'+TRASH+'</button></span>';}
    const pin=m.pinned?'<span class="pin" title="Pinned">'+PIN+'</span>':'';
    return '<div class="msg'+(m.pinned?' pinned':'')+'"><div class="meta">'+pin+'<b>'+esc(m.author)+'</b> <span class="muted">'+timeago(m.created)+'</span>'+btns
      +'</div><div class="body">'+linkify(m.content)+'</div></div>';}).join('');
  if(atBottom)el.scrollTop=el.scrollHeight;}
async function postMessage(){if(!me){openAuth();return;}if(currentThread===null)return;const inp=msgInput,content=inp.value.trim();if(!content)return;
  try{await api('/api/messages',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'thread='+currentThread+'&content='+encodeURIComponent(content)});}catch(e){return;}
  inp.value='';await loadMessages();}
// ---- admin actions ----
async function delThread(id){if(!confirm('Delete this thread and all its messages?'))return;
  try{await api('/api/admin/thread/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id});}catch(e){return;}
  if(currentThread===id){currentThread=null;composer.style.display='none';threadTitle.textContent='Select a thread';messages.innerHTML='';}
  loadThreads();}
async function delMsg(id){if(!confirm('Delete this message?'))return;
  try{await api('/api/admin/message/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id});}catch(e){return;}
  loadMessages();}
async function pinThread(id,p){try{await api('/api/admin/thread/pin',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id+'&pinned='+p});}catch(e){return;}loadThreads();}
async function pinMsg(id,p){try{await api('/api/admin/message/pin',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id+'&pinned='+p});}catch(e){return;}loadMessages();}
// ---- input handlers ----
msgInput.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();postMessage();}});
newThreadTitle.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();createThread();}});
authPass.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();doAuth();}});
authUser.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();authPass.focus();}});
// ---- voice (desktop client only) ----
function nativeMsg(o){ if(IN_CLIENT) window.chrome.webview.postMessage(JSON.stringify(o)); }
function voiceRoomFor(){ return currentThread!==null ? ('t'+currentThread) : null; }
function updateVoiceUI(){ voicebar.style.display=(IN_CLIENT&&me&&currentThread!==null)?'flex':'none'; }
async function voiceToggle(){ if(voiceOn) await voiceLeave(); else await voiceJoin(); }
async function voiceJoin(){ const room=voiceRoomFor(); if(!room||!me)return; let r;
  try{ r=await api('/api/voice/join',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(room)});}catch(e){return;}
  const d=await r.json(); nativeMsg({type:'voice-join',token:d.token,port:d.port});
  voiceOn=true;voiceRoom=room;voiceBtn.textContent='Leave voice';voiceMuteBtn.style.display='';
  voiceMemTimer=setInterval(voicePollMembers,3000);voicePollMembers(); }
async function voiceLeave(){ if(voiceRoom){ try{ await fetch('/api/voice/leave',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(voiceRoom)});}catch(e){} }
  nativeMsg({type:'voice-leave'}); voiceOn=false;voiceMuted=false;voiceRoom=null;
  voiceBtn.textContent='Join voice';voiceMuteBtn.style.display='none';voiceMuteBtn.textContent='Mute';
  if(voiceMemTimer){clearInterval(voiceMemTimer);voiceMemTimer=null;} voiceMembers.textContent=''; }
function voiceMuteToggle(){ voiceMuted=!voiceMuted; nativeMsg({type:'voice-mute',on:voiceMuted?'1':'0'}); voiceMuteBtn.textContent=voiceMuted?'Unmute':'Mute'; }
async function voicePollMembers(){ if(!voiceRoom)return; try{ const r=await fetch('/api/voice/members?room='+encodeURIComponent(voiceRoom)); const m=await r.json(); voiceMembers.textContent='In voice: '+(m.length?m.join(', '):'(just you)'); }catch(e){} }
// ---- screen share (desktop client only) ----
function screenRoomFor(){ return currentThread!==null ? ('t'+currentThread+':screen') : null; }
function updateScreenUI(){
  screenBtn.style.display=(IN_CLIENT&&me&&currentThread!==null)?'':'none';
  screenQuality.style.display=(IN_CLIENT&&me&&currentThread!==null&&!screenOn)?'':'none';
  screenBtn.textContent=screenOn?'Stop sharing':'Share screen';
  if(IN_CLIENT&&currentThread!==null){ if(!screenStatusTimer){screenStatusTimer=setInterval(screenPollStatus,3000);} screenPollStatus(); }
  else { if(screenStatusTimer){clearInterval(screenStatusTimer);screenStatusTimer=null;} screenSharers.textContent=''; }
}
async function screenToggle(){ if(screenOn) await screenStopShare(); else await screenStartShare(); }
async function screenStartShare(){ const room=screenRoomFor(); if(!room||!me)return; screenShareQuality=parseInt(screenQuality.value)||0; let r;
  try{ r=await api('/api/screen/start',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(room)+'&quality='+screenShareQuality});}catch(e){return;}
  const d=await r.json(); nativeMsg({type:'screen-share-start',token:d.token,port:d.port,quality:screenShareQuality});
  screenOn=true;screenShareRoom=room;screenBtn.textContent='Stop sharing';screenQuality.style.display='none';
  if(screenAnnTimer)clearInterval(screenAnnTimer);
  screenAnnTimer=setInterval(()=>{ if(screenShareRoom) fetch('/api/screen/start',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(screenShareRoom)+'&quality='+screenShareQuality}).catch(()=>{}); },5000); }
async function screenStopShare(){ if(screenShareRoom){ try{ await fetch('/api/screen/stop',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(screenShareRoom)});}catch(e){} }
  nativeMsg({type:'screen-share-stop'}); screenOn=false;screenShareRoom=null;screenBtn.textContent='Share screen';screenQuality.style.display='';
  if(screenAnnTimer){clearInterval(screenAnnTimer);screenAnnTimer=null;} }
async function screenView(name,layers){ const room=screenRoomFor(); if(!room)return; if(screenViewing===name)return; let r;
  try{ r=await api('/api/screen/view',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'room='+encodeURIComponent(room)});}catch(e){return;}
  const d=await r.json(); screenViewLayers=layers||1; screenViewLayer=Math.min(1,screenViewLayers-1);
  nativeMsg({type:'screen-view-start',token:d.token,port:d.port,name:name,layer:screenViewLayer}); screenViewing=name; screenPollStatus(); }
function screenStopView(){ nativeMsg({type:'screen-view-stop'}); screenViewing=null; screenPollStatus(); }
function screenSetViewQuality(layer){ screenViewLayer=layer; nativeMsg({type:'screen-view-quality',layer:layer}); }
async function screenPollStatus(){ const room=screenRoomFor(); if(!room){screenSharers.textContent='';return;}
  let list=[]; try{ const r=await fetch('/api/screen/status?room='+encodeURIComponent(room)); const d=await r.json(); list=d.sharers||[]; }catch(e){return;}
  const others=list.filter(s=>s.name!==me);
  if(screenViewing && !others.some(s=>s.name===screenViewing)) screenStopView();
  const el=screenSharers; el.innerHTML='';
  if(screenViewing){ el.appendChild(document.createTextNode('Viewing '+screenViewing+'’s screen '));
    if(screenViewLayers>1){ const sel=document.createElement('select'); sel.className='ghost';
      for(let i=0;i<screenViewLayers;i++){ const op=document.createElement('option'); op.value=i; op.textContent=LAYER_LABELS[i]; if(i===screenViewLayer)op.selected=true; sel.appendChild(op); }
      sel.onchange=()=>screenSetViewQuality(parseInt(sel.value)); el.appendChild(sel); el.appendChild(document.createTextNode(' ')); }
    const b=document.createElement('a'); b.href='#'; b.textContent='(stop)'; b.onclick=(ev)=>{ev.preventDefault();screenStopView();}; el.appendChild(b); return; }
  others.forEach((s,i)=>{ if(i)el.appendChild(document.createTextNode(' ')); const b=document.createElement('a'); b.href='#'; b.textContent='▶ View '+s.name+'’s screen'; b.onclick=(ev)=>{ev.preventDefault();screenView(s.name,s.layers);}; el.appendChild(b); }); }
(async()=>{const r=await fetch('/api/me');const d=await r.json();me=d.user;isAdmin=!!d.admin;showApp();})();
</script></body></html>)HTML";

// ===========================================================================
// HTTP plumbing
// ===========================================================================
inline void sendAll(SOCKET s,const std::string& data){ size_t sent=0;
    while(sent<data.size()){ int n=send(s,data.data()+sent,(int)(data.size()-sent),0); if(n<=0)break; sent+=n; } }
inline void sendResponse(SOCKET s,const std::string& status,const std::string& ctype,
                         const std::string& body,const std::string& extra=""){
    std::ostringstream o; o<<"HTTP/1.1 "<<status<<"\r\nContent-Type: "<<ctype
        <<"\r\nContent-Length: "<<body.size()<<"\r\nCache-Control: no-store\r\n";
    if(!extra.empty())o<<extra; o<<"Connection: close\r\n\r\n"<<body; sendAll(s,o.str());
}
inline std::string cookieSet(const std::string& tok){ return "Set-Cookie: session="+tok+"; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000\r\n"; }
inline std::string cookieClear(){ return "Set-Cookie: session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0\r\n"; }
inline std::string parseCookie(const std::string& hdr,const std::string& key){ size_t pos=0;
    while(pos<hdr.size()){ size_t semi=hdr.find(';',pos); if(semi==std::string::npos)semi=hdr.size();
        std::string kv=trimStr(hdr.substr(pos,semi-pos)); size_t eq=kv.find('=');
        if(eq!=std::string::npos&&trimStr(kv.substr(0,eq))==key) return trimStr(kv.substr(eq+1));
        pos=semi+1; }
    return "";
}

// ===========================================================================
// Voice chat rooms  (UDP relay through this server; no P2P, no STUN/TURN)
//
//   client --HTTP /api/voice/join--> get {token, udpPort, members}
//   client --UDP HELLO(token)------> server: bind srcAddr->account/room, WELCOME(id)
//   client --UDP AUDIO(id,seq,opus)-> server: forward to every other id in the room
//   server keeps NAT open via the client's own PINGs; audio is Opus frames.
// ===========================================================================
static const unsigned char VOICE_HELLO   = 0x01;
static const unsigned char VOICE_WELCOME = 0x02;
static const unsigned char VOICE_AUDIO   = 0x03;
static const unsigned char VOICE_PING    = 0x04;
static const unsigned char VOICE_VIDEO   = 0x05;   // screen-share fragments (relayed like audio)
static const unsigned char VOICE_SUBSCRIBE = 0x06; // viewer picks which simulcast layer it wants

struct VoiceToken { std::string account; std::string room; long long expiry; };
struct VoicePeer  { sockaddr_in addr; std::string account; std::string room; uint16_t id; long long lastSeen; int vlayer = 255; };

inline std::mutex g_voiceMutex;
inline std::unordered_map<std::string, VoiceToken> g_voiceTokens;   // token -> pending join
inline std::unordered_map<uint16_t, VoicePeer>     g_voicePeers;    // senderId -> peer
inline std::unordered_map<std::string, std::set<uint16_t>> g_voiceRooms; // room -> senderIds
inline uint16_t g_nextVoiceId = 1;
inline SOCKET   g_voiceSock = INVALID_SOCKET;
inline std::thread g_voiceThread;

inline std::string voiceCreateToken(const std::string& account, const std::string& room){
    auto r = randomBytes(8); std::string tok = toHex(r.data(), 8);   // 16 hex chars
    std::lock_guard<std::mutex> lk(g_voiceMutex);
    g_voiceTokens[tok] = { account, room, (long long)time(nullptr) + 15 };
    return tok;
}
inline std::string voiceMembersJson(const std::string& room){
    std::lock_guard<std::mutex> lk(g_voiceMutex);
    std::set<std::string> names;
    auto it = g_voiceRooms.find(room);
    if(it != g_voiceRooms.end())
        for(uint16_t id : it->second){ auto p = g_voicePeers.find(id); if(p != g_voicePeers.end()) names.insert(p->second.account); }
    std::ostringstream o; o << "["; bool first = true;
    for(const auto& n : names){ if(!first) o << ","; first = false; o << "\"" << jsonEscape(n) << "\""; }
    o << "]"; return o.str();
}
inline void voiceLeaveAccount(const std::string& account, const std::string& room){
    std::lock_guard<std::mutex> lk(g_voiceMutex);
    for(auto it = g_voicePeers.begin(); it != g_voicePeers.end(); ){
        if(it->second.account == account && (room.empty() || it->second.room == room)){
            auto rit = g_voiceRooms.find(it->second.room);
            if(rit != g_voiceRooms.end()) rit->second.erase(it->first);
            it = g_voicePeers.erase(it);
        } else ++it;
    }
}
// ---- screen-share signaling (who is sharing in a room) ----
// The video itself rides the same UDP relay as voice; this only announces
// availability so viewers know to open a stream. Entries expire unless the
// sharer re-announces (client does so every few seconds), so a crashed sharer
// clears on its own.
struct ScreenShare { long long expiry; int layers; };   // layers = how many simulcast layers the sharer sends
inline std::mutex g_screenMutex;
inline std::unordered_map<std::string, std::unordered_map<std::string, ScreenShare>> g_screenSharers; // room -> (account -> share)
inline void screenAnnounce(const std::string& account, const std::string& room, int layers){
    std::lock_guard<std::mutex> lk(g_screenMutex);
    g_screenSharers[room][account] = { (long long)time(nullptr) + 12, layers < 1 ? 1 : (layers > 3 ? 3 : layers) };
}
inline void screenStopShare(const std::string& account, const std::string& room){
    std::lock_guard<std::mutex> lk(g_screenMutex);
    auto it = g_screenSharers.find(room);
    if(it != g_screenSharers.end()){ it->second.erase(account); if(it->second.empty()) g_screenSharers.erase(it); }
}
inline bool screenIsSharing(const std::string& account, const std::string& room){   // already an active sharer? (skips re-announce log spam)
    long long now = (long long)time(nullptr);
    std::lock_guard<std::mutex> lk(g_screenMutex);
    auto it = g_screenSharers.find(room); if(it == g_screenSharers.end()) return false;
    auto sit = it->second.find(account); return sit != it->second.end() && sit->second.expiry >= now;
}
inline std::string screenSharersJson(const std::string& room){
    long long now = (long long)time(nullptr);
    std::lock_guard<std::mutex> lk(g_screenMutex);
    std::ostringstream o; o << "["; bool first = true;
    auto it = g_screenSharers.find(room);
    if(it != g_screenSharers.end())
        for(auto sit = it->second.begin(); sit != it->second.end(); ){
            if(sit->second.expiry < now){ sit = it->second.erase(sit); continue; }
            if(!first) o << ","; first = false;
            o << "{\"name\":\"" << jsonEscape(sit->first) << "\",\"layers\":" << sit->second.layers << "}"; ++sit;
        }
    o << "]"; return o.str();
}

// The UDP relay loop (one thread). SO_RCVTIMEO lets it also reap stale peers.
inline void voiceRelayLoop(){
    char buf[4096];
    long long lastPurge = (long long)time(nullptr);
    while(g_running){
        sockaddr_in from{}; int fl = sizeof(from);
        int n = recvfrom(g_voiceSock, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        long long now = (long long)time(nullptr);
        if(n > 0){
            unsigned char type = (unsigned char)buf[0];
            if(type == VOICE_HELLO && n >= 17){
                std::string tok(buf + 1, 16);
                std::lock_guard<std::mutex> lk(g_voiceMutex);
                auto t = g_voiceTokens.find(tok);
                if(t != g_voiceTokens.end() && t->second.expiry >= now){
                    VoicePeer p; p.addr = from; p.account = t->second.account; p.room = t->second.room; p.lastSeen = now;
                    uint16_t id = g_nextVoiceId++; if(g_nextVoiceId == 0) g_nextVoiceId = 1;
                    p.id = id; g_voicePeers[id] = p; g_voiceRooms[p.room].insert(id);
                    logLine(p.account + " UDP connected for room '" + p.room + "' [from " + ipStr(from) + "] - voice/screen can flow");
                    g_voiceTokens.erase(t);
                    char w[3]; w[0] = VOICE_WELCOME; memcpy(w + 1, &id, 2);
                    sendto(g_voiceSock, w, 3, 0, (sockaddr*)&from, sizeof(from));
                }
            } else if(type == VOICE_AUDIO && n >= 3){
                uint16_t sid; memcpy(&sid, buf + 1, 2);   // audio: forward to every other peer in the room
                std::lock_guard<std::mutex> lk(g_voiceMutex);
                auto p = g_voicePeers.find(sid);
                if(p != g_voicePeers.end()){
                    p->second.lastSeen = now;
                    auto rit = g_voiceRooms.find(p->second.room);
                    if(rit != g_voiceRooms.end())
                        for(uint16_t oid : rit->second){ if(oid == sid) continue;
                            auto op = g_voicePeers.find(oid);
                            if(op != g_voicePeers.end())
                                sendto(g_voiceSock, buf, n, 0, (sockaddr*)&op->second.addr, sizeof(op->second.addr)); }
                }
            } else if(type == VOICE_VIDEO && n >= 13){
                uint16_t sid; memcpy(&sid, buf + 1, 2);   // video: forward only to peers subscribed to this layer
                unsigned char layer = (unsigned char)buf[12];
                std::lock_guard<std::mutex> lk(g_voiceMutex);
                auto p = g_voicePeers.find(sid);
                if(p != g_voicePeers.end()){
                    p->second.lastSeen = now;
                    auto rit = g_voiceRooms.find(p->second.room);
                    if(rit != g_voiceRooms.end())
                        for(uint16_t oid : rit->second){ if(oid == sid) continue;
                            auto op = g_voicePeers.find(oid);
                            if(op == g_voicePeers.end()) continue;
                            int want = op->second.vlayer; if(want == 255) want = 0;   // default to base layer until they subscribe
                            if(want == (int)layer)
                                sendto(g_voiceSock, buf, n, 0, (sockaddr*)&op->second.addr, sizeof(op->second.addr)); }
                }
            } else if(type == VOICE_SUBSCRIBE && n >= 4){
                uint16_t sid; memcpy(&sid, buf + 1, 2);
                std::lock_guard<std::mutex> lk(g_voiceMutex);
                auto p = g_voicePeers.find(sid); if(p != g_voicePeers.end()){ p->second.lastSeen = now; p->second.vlayer = (unsigned char)buf[3]; }
            } else if(type == VOICE_PING && n >= 3){
                uint16_t sid; memcpy(&sid, buf + 1, 2);
                std::lock_guard<std::mutex> lk(g_voiceMutex);
                auto p = g_voicePeers.find(sid); if(p != g_voicePeers.end()) p->second.lastSeen = now;
            }
        }
        if(now - lastPurge >= 5){   // reap peers gone quiet, and expired tokens
            lastPurge = now;
            std::lock_guard<std::mutex> lk(g_voiceMutex);
            for(auto it = g_voicePeers.begin(); it != g_voicePeers.end(); ){
                if(now - it->second.lastSeen > 12){
                    auto rit = g_voiceRooms.find(it->second.room);
                    if(rit != g_voiceRooms.end()) rit->second.erase(it->first);
                    it = g_voicePeers.erase(it);
                } else ++it;
            }
            for(auto it = g_voiceTokens.begin(); it != g_voiceTokens.end(); )
                { if(it->second.expiry < now) it = g_voiceTokens.erase(it); else ++it; }
        }
    }
}

inline void handleClient(SOCKET client){
    std::string peer; { sockaddr_in pa{}; int pl=sizeof(pa); if(getpeername(client,(sockaddr*)&pa,&pl)==0) peer=ipStr(pa); }
    std::string req; char buf[4096]; size_t hEnd=std::string::npos;
    while(true){ int n=recv(client,buf,sizeof(buf),0); if(n<=0)break; req.append(buf,n);
        hEnd=req.find("\r\n\r\n"); if(hEnd!=std::string::npos)break; if(req.size()>(1u<<20))break; }
    if(hEnd==std::string::npos){ closesocket(client); return; }
    std::string headerBlock=req.substr(0,hEnd), body=req.substr(hEnd+4);
    std::istringstream hs(headerBlock); std::string reqLine; std::getline(hs,reqLine);
    if(!reqLine.empty()&&reqLine.back()=='\r')reqLine.pop_back();
    std::istringstream rl(reqLine); std::string method,target,version; rl>>method>>target>>version;
    size_t contentLength=0; std::string cookieHeader,h;
    while(std::getline(hs,h)){ if(!h.empty()&&h.back()=='\r')h.pop_back(); size_t colon=h.find(':');
        if(colon==std::string::npos)continue; std::string key=toLower(h.substr(0,colon)),val=trimStr(h.substr(colon+1));
        if(key=="content-length"){ try{ contentLength=(size_t)std::stoul(val);}catch(...){} }
        else if(key=="cookie") cookieHeader=val; }
    while(body.size()<contentLength){ int n=recv(client,buf,sizeof(buf),0); if(n<=0)break; body.append(buf,n); }
    std::string path=target,query; size_t qm=target.find('?');
    if(qm!=std::string::npos){ path=target.substr(0,qm); query=target.substr(qm+1); }
    std::string token=parseCookie(cookieHeader,"session");
    std::string currentUser=userForToken(token);
    if(!currentUser.empty()&&isBannedUser(currentUser)){ logoutToken(token); currentUser.clear(); }
    if(!currentUser.empty()) touchSession(token);  // presence heartbeat

    // ---- public routes ----
    if(method=="GET"&&(path=="/"||path=="/index.html")){ sendResponse(client,"200 OK","text/html; charset=utf-8",PAGE_HTML); closesocket(client); return; }
    if(method=="GET"&&path=="/api/me"){
        bool adm = !currentUser.empty() && isAdminUser(currentUser);
        std::string b = currentUser.empty()
            ? std::string("{\"user\":null,\"admin\":false}")
            : std::string("{\"user\":\"")+jsonEscape(currentUser)+"\",\"admin\":"+(adm?"true":"false")+"}";
        sendResponse(client,"200 OK","application/json",b); closesocket(client); return;
    }
    if(method=="POST"&&(path=="/api/register"||path=="/api/login")){
        auto f=parseForm(body); std::string uname=f["username"],pass=f["password"],err;
        std::string tok=(path=="/api/register")?registerUser(uname,pass,&err):loginUser(uname,pass,&err);
        if(tok.empty()) sendResponse(client,"400 Bad Request","application/json",std::string("{\"error\":\"")+jsonEscape(err)+"\"}");
        else { std::string who=userForToken(tok); bool adm=isAdminUser(who);
            sendResponse(client,"200 OK","application/json",
                std::string("{\"user\":\"")+jsonEscape(who)+"\",\"admin\":"+(adm?"true":"false")+"}", cookieSet(tok)); }
        closesocket(client); return;
    }
    if(method=="POST"&&path=="/api/logout"){ logoutToken(token);
        sendResponse(client,"200 OK","application/json","{\"ok\":true}",cookieClear()); closesocket(client); return; }

    // ---- public read routes (browsing threads/messages needs no account) ----
    if(method=="GET"&&path=="/api/threads"){ sendResponse(client,"200 OK","application/json",threadsJson()); closesocket(client); return; }
    if(method=="GET"&&path=="/api/messages"){ auto f=parseForm(query); long long tid=0;
        try{ tid=std::stoll(f["thread"]); }catch(...){}
        sendResponse(client,"200 OK","application/json",messagesJson(tid)); closesocket(client); return; }

    // ---- routes below require a signed-in account (posting + admin) ----
    if(currentUser.empty()){ sendResponse(client,"401 Unauthorized","application/json","{\"error\":\"login required\"}"); closesocket(client); return; }

    bool admin = isAdminUser(currentUser);
    if(method=="POST"&&path=="/api/ping"){ // "still here" heartbeat (touchSession already ran above)
        std::ostringstream o; o<<"{\"ok\":true,\"online\":"<<onlineCount()<<"}";
        sendResponse(client,"200 OK","application/json",o.str());
    }
    else if(method=="POST"&&path=="/api/voice/join"){ auto f=parseForm(body); std::string room=trimStr(f["room"]);
        if(room.empty()) sendResponse(client,"400 Bad Request","application/json","{\"error\":\"room required\"}");
        else { std::string tok=voiceCreateToken(currentUser,room);
            logLine(currentUser+" requested voice for room '"+room+"' [HTTP from "+peer+"] - awaiting UDP");
            std::ostringstream o; o<<"{\"token\":\""<<tok<<"\",\"port\":"<<g_port<<",\"members\":"<<voiceMembersJson(room)<<"}";
            sendResponse(client,"200 OK","application/json",o.str()); } }
    else if(method=="POST"&&path=="/api/voice/leave"){ auto f=parseForm(body); std::string room=trimStr(f["room"]);
        voiceLeaveAccount(currentUser,room);
        sendResponse(client,"200 OK","application/json","{\"ok\":true}"); }
    else if(method=="GET"&&path=="/api/voice/members"){ auto f=parseForm(query); std::string room=trimStr(f["room"]);
        sendResponse(client,"200 OK","application/json",voiceMembersJson(room)); }
    else if(method=="POST"&&path=="/api/screen/start"){ auto f=parseForm(body); std::string room=trimStr(f["room"]);
        int q=0; try{ q=std::stoi(trimStr(f["quality"])); }catch(...){}   // 0=low,1=balanced,2=high -> 1..3 layers
        int layers = q<=0 ? 1 : (q==1 ? 2 : 3);
        if(room.empty()) sendResponse(client,"400 Bad Request","application/json","{\"error\":\"room required\"}");
        else { bool fresh=!screenIsSharing(currentUser,room); screenAnnounce(currentUser,room,layers); std::string tok=voiceCreateToken(currentUser,room);
            if(fresh) logLine(currentUser+" started screen share in room '"+room+"' ("+std::to_string(layers)+" layer(s)) [HTTP from "+peer+"] - awaiting UDP");
            std::ostringstream o; o<<"{\"token\":\""<<tok<<"\",\"port\":"<<g_port<<",\"layers\":"<<layers<<"}";
            sendResponse(client,"200 OK","application/json",o.str()); } }
    else if(method=="POST"&&path=="/api/screen/stop"){ auto f=parseForm(body); std::string room=trimStr(f["room"]);
        screenStopShare(currentUser,room); logLine(currentUser+" stopped screen share in room '"+room+"'");
        sendResponse(client,"200 OK","application/json","{\"ok\":true}"); }
    else if(method=="POST"&&path=="/api/screen/view"){ auto f=parseForm(body); std::string room=trimStr(f["room"]);
        if(room.empty()) sendResponse(client,"400 Bad Request","application/json","{\"error\":\"room required\"}");
        else { std::string tok=voiceCreateToken(currentUser,room);
            logLine(currentUser+" requested to view screen in room '"+room+"' [HTTP from "+peer+"] - awaiting UDP");
            std::ostringstream o; o<<"{\"token\":\""<<tok<<"\",\"port\":"<<g_port<<"}";
            sendResponse(client,"200 OK","application/json",o.str()); } }
    else if(method=="GET"&&path=="/api/screen/status"){ auto f=parseForm(query); std::string room=trimStr(f["room"]);
        std::ostringstream o; o<<"{\"sharers\":"<<screenSharersJson(room)<<"}";
        sendResponse(client,"200 OK","application/json",o.str()); }
    else if(method=="POST"&&path=="/api/threads"){ auto f=parseForm(body); std::string title=trimStr(f["title"]);
        if(title.empty()) sendResponse(client,"400 Bad Request","application/json","{\"error\":\"title required\"}");
        else { long long id=coreCreateThread(title,currentUser);
            logLine(currentUser+" created thread '"+title+"' (#"+std::to_string(id)+") [from "+peer+"]");
            std::ostringstream o; o<<"{\"id\":"<<id<<"}"; sendResponse(client,"200 OK","application/json",o.str()); } }
    else if(method=="POST"&&path=="/api/messages"){ auto f=parseForm(body); long long tid=0;
        try{ tid=std::stoll(f["thread"]); }catch(...){}
        std::string content=trimStr(f["content"]);
        if(tid==0||content.empty()) sendResponse(client,"400 Bad Request","application/json","{\"error\":\"thread and content required\"}");
        else if(!coreThreadExists(tid)) sendResponse(client,"404 Not Found","application/json","{\"error\":\"no such thread\"}");
        else { long long id=corePostMessage(tid,currentUser,content);
            logLine(currentUser+" posted in thread #"+std::to_string(tid)+" [from "+peer+"]");
            std::ostringstream o; o<<"{\"id\":"<<id<<"}"; sendResponse(client,"200 OK","application/json",o.str()); } }
    else if(method=="POST"&&path=="/api/admin/thread/delete"){
        if(!admin){ sendResponse(client,"403 Forbidden","application/json","{\"error\":\"admin only\"}"); }
        else { auto f=parseForm(body); long long id=0; try{ id=std::stoll(f["id"]); }catch(...){}
            coreDeleteThread(id); logLine(currentUser+" deleted thread "+std::to_string(id));
            sendResponse(client,"200 OK","application/json","{\"ok\":true}"); } }
    else if(method=="POST"&&path=="/api/admin/message/delete"){
        if(!admin){ sendResponse(client,"403 Forbidden","application/json","{\"error\":\"admin only\"}"); }
        else { auto f=parseForm(body); long long id=0; try{ id=std::stoll(f["id"]); }catch(...){}
            coreDeleteMessage(id); logLine(currentUser+" deleted message "+std::to_string(id));
            sendResponse(client,"200 OK","application/json","{\"ok\":true}"); } }
    else if(method=="POST"&&path=="/api/admin/thread/pin"){
        if(!admin){ sendResponse(client,"403 Forbidden","application/json","{\"error\":\"admin only\"}"); }
        else { auto f=parseForm(body); long long id=0; try{ id=std::stoll(f["id"]); }catch(...){}
            bool pin=(trimStr(f["pinned"])=="1"); coreSetThreadPinned(id,pin);
            logLine(currentUser+(pin?" pinned":" unpinned")+" thread "+std::to_string(id));
            sendResponse(client,"200 OK","application/json","{\"ok\":true}"); } }
    else if(method=="POST"&&path=="/api/admin/message/pin"){
        if(!admin){ sendResponse(client,"403 Forbidden","application/json","{\"error\":\"admin only\"}"); }
        else { auto f=parseForm(body); long long id=0; try{ id=std::stoll(f["id"]); }catch(...){}
            bool pin=(trimStr(f["pinned"])=="1"); coreSetMessagePinned(id,pin);
            logLine(currentUser+(pin?" pinned":" unpinned")+" message "+std::to_string(id));
            sendResponse(client,"200 OK","application/json","{\"ok\":true}"); } }
    else sendResponse(client,"404 Not Found","text/plain","Not found");
    closesocket(client);
}

// ===========================================================================
// Server lifecycle
// ===========================================================================
// Best-effort: allow this exe through Windows Firewall (inbound). Works only
// when the process is elevated; otherwise it silently does nothing, so there is
// no harm in always attempting it.
inline void tryAddFirewallRule(){
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INetFwPolicy2* policy=nullptr;
    if(SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2),(void**)&policy)) && policy){
        INetFwRules* rules=nullptr;
        if(SUCCEEDED(policy->get_Rules(&rules)) && rules){
            wchar_t exe[MAX_PATH]; GetModuleFileNameW(nullptr,exe,MAX_PATH);
            // TCP carries HTTP/messaging; UDP carries voice + screen-share. Add both.
            struct { const wchar_t* name; LONG proto; } specs[] = {
                { L"Messager Server (TCP)", NET_FW_IP_PROTOCOL_TCP },
                { L"Messager Server (UDP)", NET_FW_IP_PROTOCOL_UDP },
            };
            { BSTR old=SysAllocString(L"Messager Server"); rules->Remove(old); SysFreeString(old); }  // remove legacy TCP-only rule
            for(auto& sp : specs){
                BSTR name=SysAllocString(sp.name);
                rules->Remove(name);                        // avoid duplicates
                INetFwRule* rule=nullptr;
                if(SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,
                                              __uuidof(INetFwRule),(void**)&rule)) && rule){
                    BSTR app=SysAllocString(exe);
                    rule->put_Name(name);
                    rule->put_ApplicationName(app);
                    rule->put_Protocol(sp.proto);
                    rule->put_Direction(NET_FW_RULE_DIR_IN);
                    rule->put_Action(NET_FW_ACTION_ALLOW);
                    rule->put_Enabled(VARIANT_TRUE);
                    rules->Add(rule);                        // requires admin; ignored otherwise
                    SysFreeString(app);
                    rule->Release();
                }
                SysFreeString(name);
            }
            rules->Release();
        }
        policy->Release();
    }
    if(SUCCEEDED(hrCo)) CoUninitialize();
}
inline bool startServer(int port,std::string& err){
    if(g_running){ err="Server already running."; return false; }
    tryAddFirewallRule();
    if(!g_wsaInit){ WSADATA w; if(WSAStartup(MAKEWORD(2,2),&w)!=0){ err="WSAStartup failed."; return false; } g_wsaInit=true; }
    SOCKET l=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(l==INVALID_SOCKET){ err="socket() failed."; return false; }
    int yes=1; setsockopt(l,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons((u_short)port); a.sin_addr.s_addr=INADDR_ANY;
    if(bind(l,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR){ err="Port "+std::to_string(port)+" is already in use."; closesocket(l); return false; }
    if(listen(l,SOMAXCONN)==SOCKET_ERROR){ err="listen() failed."; closesocket(l); return false; }
    g_listener=l; g_port=port; g_running=true;
    g_acceptThread=std::thread([](){
        while(g_running){ SOCKET c=accept(g_listener,nullptr,nullptr);
            if(c==INVALID_SOCKET){ if(!g_running)break; else continue; }
            std::thread(handleClient,c).detach(); }
    });
    // Voice relay: a UDP socket on the SAME port number (TCP/UDP are separate).
    g_voiceSock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(g_voiceSock!=INVALID_SOCKET){
        sockaddr_in va{}; va.sin_family=AF_INET; va.sin_port=htons((u_short)port); va.sin_addr.s_addr=INADDR_ANY;
        DWORD rcvTmo=2000; setsockopt(g_voiceSock,SOL_SOCKET,SO_RCVTIMEO,(char*)&rcvTmo,sizeof(rcvTmo));
        if(bind(g_voiceSock,(sockaddr*)&va,sizeof(va))==0) g_voiceThread=std::thread(voiceRelayLoop);
        else { closesocket(g_voiceSock); g_voiceSock=INVALID_SOCKET; }
    }
    logLine("Server started on port "+std::to_string(port));
    return true;
}
inline void stopServer(){
    if(!g_running)return; g_running=false;
    if(g_listener!=INVALID_SOCKET){ closesocket(g_listener); g_listener=INVALID_SOCKET; }
    if(g_voiceSock!=INVALID_SOCKET){ closesocket(g_voiceSock); g_voiceSock=INVALID_SOCKET; }
    if(g_acceptThread.joinable()) g_acceptThread.join();
    if(g_voiceThread.joinable()) g_voiceThread.join();
    { std::lock_guard<std::mutex> lk(g_voiceMutex); g_voicePeers.clear(); g_voiceRooms.clear(); g_voiceTokens.clear(); }
    logLine("Server stopped.");
}
inline void joinServer(){ if(g_acceptThread.joinable()) g_acceptThread.join(); }

// LAN IPv4 addresses of this machine.
inline std::vector<std::string> localIPs(){
    std::vector<std::string> out; char host[256];
    if(gethostname(host,sizeof(host))!=0) return out;
    addrinfo hints{}; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; addrinfo* res=nullptr;
    if(getaddrinfo(host,nullptr,&hints,&res)!=0) return out;
    for(addrinfo* p=res;p;p=p->ai_next){ char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&((sockaddr_in*)p->ai_addr)->sin_addr,ip,sizeof(ip)); out.push_back(ip); }
    freeaddrinfo(res); return out;
}
