#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <mutex>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ============================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================

bool isNumeric(const std::string& value) {
    if (value.empty()) {
        return false;
    }

    return std::all_of(
        value.begin(),
        value.end(),
        [](unsigned char c) {
            return std::isdigit(c);
        }
    );
}

bool endsWith(
    const std::string& value,
    const std::string& suffix
) {
    return value.size() >= suffix.size() &&
           value.compare(
               value.size() - suffix.size(),
               suffix.size(),
               suffix
           ) == 0;
}

// ============================================================
// ЛОГГЕР
// ============================================================

class DnsLogger {
private:
    static inline std::mutex mutex_;
    static inline std::ofstream file_;

public:
    static void init(
        const std::string& filename = "activity_log.txt"
    ) {
        std::lock_guard<std::mutex> lock(mutex_);

        const fs::path absolutePath = fs::absolute(filename);

        file_.open(
            absolutePath,
            std::ios::out | std::ios::app
        );

        std::cout << "[DNS] Log file: "
                  << absolutePath.string()
                  << '\n';

        if (!file_.is_open()) {
            std::cerr << "[DNS] Cannot open log file\n";
        }
    }

    static void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::cout << message << std::endl;

        if (file_.is_open()) {
            file_ << message << '\n';
            file_.flush();
        }
    }
};

// ============================================================
// МЕТАДАННЫЕ ПРОЦЕССА
// ============================================================

struct ProcessInfo {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string name = "<unknown>";
};

ProcessInfo getProcessInfo(unsigned long pid) {
    ProcessInfo result;
    result.pid = pid;

    if (pid == 0) {
        return result;
    }

    const std::string pidText = std::to_string(pid);

    std::ifstream statFile(
        "/proc/" + pidText + "/stat"
    );

    if (!statFile.is_open()) {
        return result;
    }

    std::string line;
    std::getline(statFile, line);

    const std::size_t openBracket = line.find('(');
    const std::size_t closeBracket = line.rfind(')');

    if (openBracket == std::string::npos ||
        closeBracket == std::string::npos ||
        closeBracket <= openBracket) {
        return result;
    }

    result.name = line.substr(
        openBracket + 1,
        closeBracket - openBracket - 1
    );

    std::istringstream rest(
        line.substr(closeBracket + 2)
    );

    char state = 0;
    rest >> state >> result.ppid;

    return result;
}

// ============================================================
// СОПОСТАВЛЕНИЕ UDP-ПОРТА С PID
// ============================================================

struct UdpSocket {
    unsigned long inode = 0;
    unsigned int localPort = 0;
};

std::vector<UdpSocket> readUdpSockets() {
    std::vector<UdpSocket> sockets;

    std::ifstream udpFile("/proc/net/udp");

    if (!udpFile.is_open()) {
        return sockets;
    }

    std::string line;
    std::getline(udpFile, line); // заголовок

    while (std::getline(udpFile, line)) {
        std::istringstream input(line);

        std::string slot;
        std::string localEndpoint;
        std::string remoteEndpoint;
        std::string state;

        input >> slot
              >> localEndpoint
              >> remoteEndpoint
              >> state;

        std::vector<std::string> columns;
        std::string column;

        while (input >> column) {
            columns.push_back(column);
        }

        // После первых четырёх полей inode находится в columns[6].
        if (columns.size() < 7) {
            continue;
        }

        const std::size_t separator =
            localEndpoint.find(':');

        if (separator == std::string::npos) {
            continue;
        }

        unsigned int port = 0;
        unsigned long inode = 0;

        try {
            port = std::stoul(
                localEndpoint.substr(separator + 1),
                nullptr,
                16
            );

            inode = std::stoul(columns[6]);
        } catch (...) {
            continue;
        }

        if (port != 0 && inode != 0) {
            sockets.push_back({inode, port});
        }
    }

    return sockets;
}

std::unordered_map<unsigned long, unsigned long>
buildInodeToPidMap(
    const std::set<unsigned long>& wantedInodes
) {
    std::unordered_map<unsigned long, unsigned long> result;

    if (wantedInodes.empty()) {
        return result;
    }

    try {
        for (const auto& processEntry :
             fs::directory_iterator("/proc")) {

            const std::string pidText =
                processEntry.path().filename().string();

            if (!isNumeric(pidText)) {
                continue;
            }

            unsigned long pid = 0;

            try {
                pid = std::stoul(pidText);
            } catch (...) {
                continue;
            }

            const fs::path fdDirectory =
                processEntry.path() / "fd";

            for (const auto& fdEntry :
                 fs::directory_iterator(
                     fdDirectory,
                     fs::directory_options::skip_permission_denied
                 )) {

                char linkBuffer[PATH_MAX]{};

                const ssize_t length = readlink(
                    fdEntry.path().c_str(),
                    linkBuffer,
                    sizeof(linkBuffer) - 1
                );

                if (length <= 0) {
                    continue;
                }

                linkBuffer[length] = '\0';

                const std::string target = linkBuffer;

                if (target.rfind("socket:[", 0) != 0) {
                    continue;
                }

                const std::size_t end = target.find(']');

                if (end == std::string::npos) {
                    continue;
                }

                unsigned long inode = 0;

                try {
                    inode = std::stoul(
                        target.substr(8, end - 8)
                    );
                } catch (...) {
                    continue;
                }

                if (wantedInodes.find(inode) !=
                    wantedInodes.end()) {

                    result[inode] = pid;
                }
            }
        }
    } catch (...) {
    }

    return result;
}

std::unordered_map<unsigned int, unsigned long>
buildPortToPidMap() {
    std::unordered_map<unsigned int, unsigned long> result;

    const std::vector<UdpSocket> sockets =
        readUdpSockets();

    std::set<unsigned long> wantedInodes;

    for (const auto& socket : sockets) {
        wantedInodes.insert(socket.inode);
    }

    const auto inodeToPid =
        buildInodeToPidMap(wantedInodes);

    for (const auto& socket : sockets) {
        const auto owner =
            inodeToPid.find(socket.inode);

        if (owner != inodeToPid.end()) {
            result[socket.localPort] = owner->second;
        }
    }

    return result;
}

// ============================================================
// DNS-ПАРСЕР
// ============================================================

bool parseDnsName(
    const unsigned char* data,
    std::size_t size,
    std::size_t offset,
    std::string& name
) {
    name.clear();

    if (data == nullptr || offset >= size) {
        return false;
    }

    std::size_t position = offset;
    bool firstLabel = true;

    while (position < size) {
        const unsigned char labelLength =
            data[position++];

        if (labelLength == 0) {
            break;
        }

        // DNS compression в вопросах здесь не разбираем.
        if ((labelLength & 0xC0) != 0) {
            return false;
        }

        if (labelLength > 63 ||
            position + labelLength > size) {
            return false;
        }

        if (!firstLabel) {
            name += '.';
        }

        for (std::size_t i = 0;
             i < labelLength;
             ++i) {

            const unsigned char c =
                data[position + i];

            if (std::isalnum(c) ||
                c == '-' ||
                c == '_') {
                name += static_cast<char>(c);
            } else {
                name += '?';
            }
        }

        position += labelLength;
        firstLabel = false;
    }

    return !name.empty();
}

// ============================================================
// DNS WATCHER
// ============================================================

class DnsWatcher {
private:
    pcap_t* capture_ = nullptr;
    std::string interfaceName_;

    std::mutex seenMutex_;

    std::unordered_map<
        std::string,
        std::chrono::steady_clock::time_point
    > seenQueries_;

    static constexpr int SNAPLEN = 65535;
    static constexpr int TIMEOUT_MS = 1000;

    bool alreadySeen(
        unsigned long pid,
        const std::string& domain
    ) {
        const std::string key =
            std::to_string(pid) + "|" + domain;

        const auto now =
            std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lock(seenMutex_);

        const auto it = seenQueries_.find(key);

        if (it != seenQueries_.end()) {
            const auto age =
                std::chrono::duration_cast<
                    std::chrono::seconds
                >(now - it->second).count();

            if (age < 3) {
                return true;
            }
        }

        seenQueries_[key] = now;
        return false;
    }

    void processPacket(
        const pcap_pkthdr* header,
        const unsigned char* packet
    ) {
        if (header == nullptr || packet == nullptr) {
            return;
        }

        const int datalink = pcap_datalink(capture_);
        std::size_t networkOffset = 0;

        if (datalink == DLT_EN10MB) {
            networkOffset = 14;
        } else if (datalink == DLT_LINUX_SLL) {
            networkOffset = 16;
        } else {
            return;
        }

        if (header->caplen < networkOffset + 20) {
            return;
        }

        const unsigned char* ip =
            packet + networkOffset;

        const unsigned char version = ip[0] >> 4;
        const unsigned char ipHeaderLength =
            (ip[0] & 0x0F) * 4;

        if (version != 4 ||
            ipHeaderLength < 20 ||
            header->caplen < networkOffset + ipHeaderLength + 8) {
            return;
        }

        if (ip[9] != IPPROTO_UDP) {
            return;
        }

        const unsigned char* udp =
            ip + ipHeaderLength;

        const unsigned short sourcePort =
            static_cast<unsigned short>(
                udp[0] << 8 | udp[1]
            );

        const unsigned short destinationPort =
            static_cast<unsigned short>(
                udp[2] << 8 | udp[3]
            );

        if (destinationPort != 53) {
            return;
        }

        const std::size_t dnsOffset =
            networkOffset + ipHeaderLength + 8;

        if (header->caplen < dnsOffset + 12) {
            return;
        }

        const unsigned char* dns =
            packet + dnsOffset;

        const unsigned short flags =
            static_cast<unsigned short>(
                dns[2] << 8 | dns[3]
            );

        // QR=0 — DNS-запрос, QR=1 — ответ.
        if ((flags & 0x8000) != 0) {
            return;
        }

        const unsigned short questionCount =
            static_cast<unsigned short>(
                dns[4] << 8 | dns[5]
            );

        if (questionCount == 0) {
            return;
        }

        std::string domain;

        if (!parseDnsName(
                dns,
                header->caplen - dnsOffset,
                12,
                domain
            )) {
            return;
        }

        // Игнорируем служебные локальные запросы.
        if (domain == "localhost" ||
            endsWith(domain, ".local") ||
            endsWith(domain, ".arpa")) {
            return;
        }

        const auto portToPid =
            buildPortToPidMap();

        unsigned long pid = 0;
        ProcessInfo process;

        const auto owner =
            portToPid.find(sourcePort);

        if (owner != portToPid.end()) {
            pid = owner->second;
            process = getProcessInfo(pid);
        }

        if (alreadySeen(pid, domain)) {
            return;
        }

        std::stringstream message;

        message << "[DNS_QUERY] PID: "
                << pid
                << " | PPID: "
                << process.ppid
                << " | App: ["
                << process.name
                << "] -> "
                << domain;

        DnsLogger::log(message.str());
    }

    static void packetCallback(
        unsigned char* userData,
        const pcap_pkthdr* header,
        const unsigned char* packet
    ) {
        auto* watcher =
            reinterpret_cast<DnsWatcher*>(userData);

        watcher->processPacket(header, packet);
    }

public:
    ~DnsWatcher() {
        if (capture_ != nullptr) {
            pcap_breakloop(capture_);
            pcap_close(capture_);
        }
    }

    bool start() {
        char errorBuffer[PCAP_ERRBUF_SIZE]{};
        pcap_if_t* devices = nullptr;

        if (pcap_findalldevs(
                &devices,
                errorBuffer
            ) == -1) {

            DnsLogger::log(
                "[DNS] Cannot list interfaces: " +
                std::string(errorBuffer)
            );

            return false;
        }

        pcap_if_t* selected = nullptr;

        for (pcap_if_t* device = devices;
             device != nullptr;
             device = device->next) {

            if (!(device->flags & PCAP_IF_LOOPBACK) &&
                device->addresses != nullptr) {
                selected = device;
                break;
            }
        }

        if (selected == nullptr) {
            selected = devices;
        }

        if (selected == nullptr) {
            DnsLogger::log(
                "[DNS] No capture interface found"
            );
            pcap_freealldevs(devices);
            return false;
        }

        interfaceName_ = selected->name;

        capture_ = pcap_open_live(
            interfaceName_.c_str(),
            SNAPLEN,
            1,
            TIMEOUT_MS,
            errorBuffer
        );

        pcap_freealldevs(devices);

        if (capture_ == nullptr) {
            DnsLogger::log(
                "[DNS] Cannot open interface: " +
                std::string(errorBuffer)
            );
            return false;
        }

        bpf_program filter{};
        const char* filterText =
            "udp dst port 53";

        if (pcap_compile(
                capture_,
                &filter,
                filterText,
                1,
                PCAP_NETMASK_UNKNOWN
            ) == -1) {

            DnsLogger::log(
                "[DNS] Cannot compile packet filter"
            );
            return false;
        }

        if (pcap_setfilter(
                capture_,
                &filter
            ) == -1) {

            pcap_freecode(&filter);

            DnsLogger::log(
                "[DNS] Cannot apply packet filter"
            );
            return false;
        }

        pcap_freecode(&filter);

        DnsLogger::log(
            "[DNS] Monitoring interface: " +
            interfaceName_
        );

        const int result = pcap_loop(
            capture_,
            0,
            &DnsWatcher::packetCallback,
            reinterpret_cast<unsigned char*>(this)
        );

        if (result < 0) {
            DnsLogger::log(
                "[DNS] Capture error: " +
                std::string(pcap_geterr(capture_))
            );
        }

        return true;
    }

    void startAsync() {
        std::thread(
            [this]() {
                start();
            }
        ).detach();
    }
};

// ============================================================
// MAIN
// ============================================================

int main() {
    if (geteuid() != 0) {
        std::cerr <<
            "Запустите программу через sudo.\n";
        return 1;
    }

    DnsLogger::init();

    DnsWatcher watcher;
    watcher.startAsync();

    DnsLogger::log(
        "[DNS] DNS watcher started"
    );

    while (true) {
        std::this_thread::sleep_for(
            std::chrono::seconds(1)
        );
    }

    return 0;
}
