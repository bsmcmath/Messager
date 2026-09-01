// server.cpp - headless console version of Messager.
// (The desktop app MessagerAdmin.exe is the recommended way to run it.)
//
// Build: cl /std:c++17 /EHsc /O2 server.cpp ws2_32.lib bcrypt.lib /Fe:Messager.exe
#include "messager_core.h"

int main(int argc, char** argv) {
    int port = 8080;
    if (argc > 1) { try { port = std::stoi(argv[1]); } catch (...) {} }

    loadAll();

    std::string err;
    if (!startServer(port, err)) { std::cerr << err << "\n"; return 1; }

    std::cout << "=====================================================\n";
    std::cout << "  Messager (console) running on port " << port << ".\n\n";
    std::cout << "    On this PC:      http://127.0.0.1:" << port << "/\n";
    for (const auto& ip : localIPs())
        std::cout << "    On your network: http://" << ip << ":" << port << "/\n";
    std::cout << "\n  For internet access, forward external port " << port << " on your\n";
    std::cout << "  router to this PC, then share http://<public-ip>:" << port << "/\n";
    std::cout << "  Data: " << kDataFile << " | Users: " << kUsersFile << "\n";
    std::cout << "  Press Ctrl+C to stop.\n";
    std::cout << "=====================================================\n";

    // Mirror the server log to the console.
    while (true) {
        for (const auto& line : drainLog()) std::cout << line << "\n";
        Sleep(400);
    }
}
