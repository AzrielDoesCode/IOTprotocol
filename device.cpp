// device.cpp
// Simple IoT device (C++) for PH-LAP simulation
// Listens for UDP challenges (nonce:uint64 + ts:uint32) and responds with:
//   mac(8) || ts_resp(4) || device_id(8)
// Modes: puf (derive key from PUF emulation) or stored (stored key baseline)
// Compile: g++ -std=c++17 device.cpp -o device -lcrypto

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using steady_clock = std::chrono::steady_clock;
using time_point = std::chrono::time_point<steady_clock>;
static const size_t HMAC_TRUNC_BYTES = 8;      // 64-bit truncated HMAC
static const uint32_t TS_WINDOW_SEC = 10;      // timestamp freshness window
static const string MASTER_SECRET = "MASTER_STATIC_SECRET"; // demo only (server-side in real design)

//////////////////////////////
// Utilities
//////////////////////////////
uint64_t now_epoch_seconds() {
    return (uint64_t)std::time(nullptr);
}

string hexify(const unsigned char* d, size_t len) {
    std::ostringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) ss << setw(2) << (int)d[i];
    return ss.str();
}

//////////////////////////////
// Simple SHA256 wrapper (returns raw bytes)
//////////////////////////////
vector<unsigned char> sha256_bytes(const vector<unsigned char>& data) {
    vector<unsigned char> out(EVP_MAX_MD_SIZE);
    unsigned int outlen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, out.data(), &outlen);
    EVP_MD_CTX_free(ctx);
    out.resize(outlen);
    return out;
}

vector<unsigned char> sha256_bytes(const string& s) {
    return sha256_bytes(vector<unsigned char>(s.begin(), s.end()));
}

//////////////////////////////
// HMAC-SHA256 and truncation
//////////////////////////////
vector<unsigned char> hmac_sha256_trunc(const vector<unsigned char>& key, const vector<unsigned char>& msg, size_t out_bytes=HMAC_TRUNC_BYTES) {
    unsigned int len = EVP_MAX_MD_SIZE;
    vector<unsigned char> mac(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), key.data(), (int)key.size(), msg.data(), msg.size(), mac.data(), &len);
    if (out_bytes > len) out_bytes = len;
    mac.resize(out_bytes);
    return mac;
}

//////////////////////////////
// File/Flash helpers
//////////////////////////////
bool ensure_dir_exists(const string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) return true;
    if (mkdir(path.c_str(), 0755) == 0) return true;
    return false;
}

//////////////////////////////
// PUF Emulator (deterministic fingerprint from device_id)
//////////////////////////////
class PUFEmulator {
public:
    PUFEmulator(const string& device_id)
        : device_id(device_id)
    {
        // deterministic seed derived from SHA-256 of device_id
        auto h = sha256_bytes(device_id);
        // use first 8 bytes as uint64 seed
        uint64_t seed = 0;
        for (int i = 0; i < 8 && i < (int)h.size(); ++i) seed = (seed << 8) | h[i];
        seed ^= 0xA5A5A5A5A5A5A5A5ULL;
        // stable 8-byte fingerprint
        fingerprint.resize(8);
        for (int i = 0; i < 8; ++i) {
            fingerprint[7-i] = (unsigned char)((seed >> (8*i)) & 0xFF);
        }
        rng.seed(seed);
    }

    // Return noisy read (flip bits with flip_prob)
    vector<unsigned char> noisy_read(double flip_prob = 0.02) {
        vector<unsigned char> b = fingerprint;
        std::uniform_real_distribution<double> d(0.0, 1.0);
        for (size_t i = 0; i < b.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                if (d(rng) < flip_prob) b[i] ^= (1 << bit);
            }
        }
        return b;
    }

    // Key derivation: H(MASTER || fp || helper) -> 16 bytes
    vector<unsigned char> derive_key(const vector<unsigned char>& noisy_fp, const vector<unsigned char>& helper) {
        vector<unsigned char> data;
        data.insert(data.end(), MASTER_SECRET.begin(), MASTER_SECRET.end());
        data.insert(data.end(), noisy_fp.begin(), noisy_fp.end());
        data.insert(data.end(), helper.begin(), helper.end());
        auto digest = sha256_bytes(data);
        digest.resize(16); // 128-bit key
        return digest;
    }

    // Build ID (12-digit) derived from fingerprint hash (for storage)
    string build_id_12() {
        auto d = sha256_bytes(fingerprint);
        // take 8 bytes and mod 10^12
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | d[i];
        uint64_t id = v % 1000000000000ULL; // 12 digits
        std::ostringstream ss; ss << setw(12) << setfill('0') << id;
        return ss.str();
    }

private:
    string device_id;
    vector<unsigned char> fingerprint;
    std::mt19937_64 rng;
};

//////////////////////////////
// Replay detector with file-backed cache
//////////////////////////////
class ReplayCache {
public:
    ReplayCache(const string& folder, size_t max_entries=5000)
        : folder(folder), max_entries(max_entries)
    {
        ensure_dir_exists(folder);
        cache_path = folder + "/cache.csv";
        load_cache();
    }

    bool is_replay(uint32_t ts) {
        uint32_t now = (uint32_t)time(nullptr);
        if (abs((int)now - (int)ts) > (int)TS_WINDOW_SEC) {
            return true; // stale
        }
        // check duplication
        if (!cache.empty() && (std::find(cache.begin(), cache.end(), ts) != cache.end())) return true;
        // accept and store
        cache.push_back(ts);
        if (cache.size() > max_entries) {
            // simple cleanup: remove oldest half
            size_t remove_count = cache.size() / 2;
            cache.erase(cache.begin(), cache.begin() + remove_count);
            persist_cache(); // write reduced cache
        } else {
            append_ts(ts);
        }
        return false;
    }

    void persist_cache() {
        ofstream f(cache_path, ios::trunc);
        if (!f) return;
        for (auto t : cache) f << t << "\n";
    }

private:
    void load_cache() {
        cache.clear();
        ifstream f(cache_path);
        if (!f) return;
        uint32_t t;
        while (f >> t) cache.push_back(t);
        // if more than max_entries, trim oldest
        if (cache.size() > max_entries) {
            cache.erase(cache.begin(), cache.begin() + (cache.size() - max_entries));
            persist_cache();
        }
    }

    void append_ts(uint32_t ts) {
        ofstream f(cache_path, ios::app);
        if (!f) return;
        f << ts << "\n";
    }

    string folder;
    string cache_path;
    vector<uint32_t> cache;
    size_t max_entries;
};

//////////////////////////////
// Device main - UDP server
//////////////////////////////
int main(int argc, char** argv) {
    // parse args (very simple)
    string mode = "puf";
    string device_id = "DEV01";
    int port = 12001;
    double flip_prob = 0.02;
    size_t cache_max = 5000;
    string base_folder = "./DEVICE";

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--mode" && i+1<argc) mode = argv[++i];
        else if (a == "--device-id" && i+1<argc) device_id = argv[++i];
        else if (a == "--port" && i+1<argc) port = stoi(argv[++i]);
        else if (a == "--flip-prob" && i+1<argc) flip_prob = stod(argv[++i]);
        else if (a == "--cache-max" && i+1<argc) cache_max = stoul(argv[++i]);
        else if (a == "--base" && i+1<argc) base_folder = argv[++i];
    }

    // folder = base/DEV_<id>
    string folder = base_folder + "/" + device_id;
    ensure_dir_exists(base_folder);
    ensure_dir_exists(folder);

    // build_id file creation if missing
    string build_path = folder + "/build_id.txt";
    ifstream bf(build_path);
    string build_id;
    if (bf) {
        getline(bf, build_id);
        bf.close();
    } else {
        PUFEmulator pe(device_id);
        build_id = pe.build_id_12();
        ofstream of(build_path);
        of << build_id << "\n";
        of.close();
    }

    cout << "[Device] id=" << device_id << " mode=" << mode << " folder=" << folder << " build_id=" << build_id << "\n";

    // prepare stored key if needed
    vector<unsigned char> stored_key(16);
    if (mode == "stored") {
        // fixed 16 bytes (demo only)
        string s = "STORED_SECRET_16B";
        stored_key.assign(s.begin(), s.end());
        if (stored_key.size() < 16) stored_key.resize(16, 0);
    }

    // instantiate PUF emulator (for derive_key when needed)
    PUFEmulator puf(device_id);

    // replay cache
    ReplayCache rcache(folder, cache_max);

    // UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        cerr << "socket create failed: " << strerror(errno) << "\n"; return 1;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "bind failed: " << strerror(errno) << "\n"; close(sock); return 1;
    }

    cout << "[Device] Listening UDP port " << port << "\n";

    // main loop
    while (true) {
        unsigned char buf[512];
        sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&peer, &plen);
        if (n < 0) {
            cerr << "recvfrom error: " << strerror(errno) << "\n"; continue;
        }
        // Expect at least 12 bytes: uint64 nonce + uint32 ts
        if (n < 12) {
            cout << "[Device] received too-small packet (" << n << ")\n"; continue;
        }
        // parse
        uint64_t nonce = 0;
        uint32_t ts = 0;
        // network order read
        for (int i = 0; i < 8; ++i) nonce = (nonce << 8) | buf[i];
        for (int i = 0; i < 4; ++i) ts = (ts << 8) | buf[8+i];

        // replay detection
        if (rcache.is_replay(ts)) {
            cout << "[Device] Reject (replay/stale) ts=" << ts << "\n";
            continue; // ignore (or optionally send rejection packet)
        }

        // derive key
        vector<unsigned char> key;
        if (mode == "stored") {
            key = stored_key;
        } else {
            auto noisy = puf.noisy_read(flip_prob);
            // no helper in this simple version
            vector<unsigned char> helper; // empty
            key = puf.derive_key(noisy, helper);
        }

        // construct message = nonce:uint64 + ts:uint32 + device_id (bytes)
        vector<unsigned char> msg;
        // nonce big-endian
        for (int i = 7; i >= 0; --i) msg.push_back((unsigned char)((nonce >> (i*8)) & 0xFF));
        for (int i = 3; i >= 0; --i) msg.push_back((unsigned char)((ts >> (i*8)) & 0xFF));
        for (char c : device_id) msg.push_back((unsigned char)c);

        // compute truncated hmac
        auto mac = hmac_sha256_trunc(key, msg, HMAC_TRUNC_BYTES);

        // build response: mac (HMAC_TRUNC_BYTES) + ts_resp(uint32) + device_id padded 8
        uint32_t ts_resp = (uint32_t)time(nullptr);
        vector<unsigned char> resp;
        resp.insert(resp.end(), mac.begin(), mac.end());
        for (int i = 3; i >= 0; --i) resp.push_back((unsigned char)((ts_resp >> (i*8)) & 0xFF));
        
            // device_id padded/truncated to 8 bytes
        string id8 = device_id;
        if (id8.size() > 8) id8 = id8.substr(0,8);
        while (id8.size() < 8) id8.push_back('\0');
        for (char c : id8) resp.push_back((unsigned char)c);

        // send back
        ssize_t s = sendto(sock, resp.data(), resp.size(), 0, (sockaddr*)&peer, plen);
        if (s < 0) cerr << "[Device] sendto failed: " << strerror(errno) << "\n";
        else {
            char peer_ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
            cout << "[Device] RESP sent to " << peer_ip << ":" << ntohs(peer.sin_port) << " ts=" << ts_resp << "\n";
        }
    }

    close(sock);
    return 0;
}
