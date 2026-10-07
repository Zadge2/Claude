// remote_tool.cpp - minimal authenticated remote status tool (POSIX, C++17)
//
// Build:  g++ -std=c++17 -O2 -o remote_tool remote_tool.cpp
// Server: ./remote_tool server <port> <token>
// Client: ./remote_tool client <host> <port> <token> <command> [args...]
//
// Only whitelisted, read-only commands are served: ping, hostname, uptime,
// time, echo <text>. No shell is ever invoked. The server is visible (logs
// every request to stdout) and binds to 127.0.0.1 unless --public is given.
// The token is sent in plaintext: use only on trusted networks or tunnel it
// through SSH/VPN/TLS.

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

static bool send_line(int fd, const std::string& s) {
    std::string out = s + "\n";
    size_t sent = 0;
    while (sent < out.size()) {
        ssize_t n = ::send(fd, out.data() + sent, out.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool recv_line(int fd, std::string& line, size_t max = 4096) {
    line.clear();
    char c;
    while (line.size() < max) {
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') return true;
        if (c != '\r') line += c;
    }
    return false;
}

// Constant-time compare to avoid leaking token contents via timing.
static bool token_eq(const std::string& a, const std::string& b) {
    unsigned char diff = a.size() != b.size();
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

static std::string handle(const std::string& cmd) {
    std::istringstream in(cmd);
    std::string name;
    in >> name;
    if (name == "ping") return "pong";
    if (name == "hostname") {
        char buf[256] = {};
        gethostname(buf, sizeof(buf) - 1);
        return buf;
    }
    if (name == "uptime") {
        std::ifstream f("/proc/uptime");
        double s = 0;
        if (!(f >> s)) return "ERR uptime unavailable";
        long t = static_cast<long>(s);
        return std::to_string(t / 3600) + "h " + std::to_string(t / 60 % 60) + "m";
    }
    if (name == "time") {
        std::time_t now = std::time(nullptr);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return buf;
    }
    if (name == "echo") {
        std::string rest;
        std::getline(in, rest);
        return rest.empty() ? "" : rest.substr(1);
    }
    return "ERR unknown command (allowed: ping hostname uptime time echo)";
}

static int run_server(int port, const std::string& token, bool pub) {
    int ls = ::socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(pub ? INADDR_ANY : INADDR_LOOPBACK);
    if (bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(ls, 8) < 0) { perror("listen"); return 1; }
    std::cout << "Listening on " << (pub ? "0.0.0.0" : "127.0.0.1") << ":" << port << "\n";

    for (;;) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int fd = accept(ls, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (fd < 0) continue;
        timeval tv{10, 0};  // drop stalled clients
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));

        std::string tok, cmd;
        if (!recv_line(fd, tok) || !token_eq(tok, token)) {
            std::cout << "[" << ip << "] auth failed\n";
            send_line(fd, "ERR auth");
        } else if (recv_line(fd, cmd)) {
            std::cout << "[" << ip << "] " << cmd << "\n";
            send_line(fd, handle(cmd));
        }
        close(fd);
    }
}

static int run_client(const std::string& host, const std::string& port,
                      const std::string& token, const std::string& cmd) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        std::cerr << "cannot resolve " << host << "\n";
        return 1;
    }
    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);
    std::string reply;
    if (!send_line(fd, token) || !send_line(fd, cmd) || !recv_line(fd, reply, 65536)) {
        std::cerr << "connection failed\n";
        close(fd);
        return 1;
    }
    std::cout << reply << "\n";
    close(fd);
    return reply.rfind("ERR", 0) == 0 ? 2 : 0;
}

int main(int argc, char** argv) {
    if (argc >= 4 && std::string(argv[1]) == "server") {
        bool pub = argc >= 5 && std::string(argv[4]) == "--public";
        return run_server(std::stoi(argv[2]), argv[3], pub);
    }
    if (argc >= 6 && std::string(argv[1]) == "client") {
        std::string cmd;
        for (int i = 5; i < argc; ++i) cmd += (i > 5 ? " " : "") + std::string(argv[i]);
        return run_client(argv[2], argv[3], argv[4], cmd);
    }
    std::cerr << "Usage:\n  " << argv[0] << " server <port> <token> [--public]\n  "
              << argv[0] << " client <host> <port> <token> <command> [args...]\n";
    return 1;
}
