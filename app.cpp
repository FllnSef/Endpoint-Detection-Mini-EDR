#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <csignal>

#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <yara.h>
#include <pcap/pcap.h>

namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

bool isNumeric(const std::string& value) {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isdigit(c);
    });
}

bool endsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string escapeJson(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b";  break;
            case '\f': ss << "\\f";  break;
            case '\n': ss << "\\n";  break;
            case '\r': ss << "\\r";  break;
            case '\t': ss << "\\t";  break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
                break;
        }
    }
    return ss.str();
}

// ============================================================================
// STRUCTURED LOGGER (WITH SEPARATE PATHS FOR PROCESS LAUNCHES & ALERTS/OPS)
// ============================================================================

class Logger {
private:
    static inline std::mutex logMutex;
    static inline std::ofstream logFile;
    static inline std::ofstream jsonFile;

    // Выделенные файлы для фонового логирования запусков процессов
    static inline std::ofstream procLogFile;
    static inline std::ofstream procJsonFile;

    static std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

public:
    static void init(const std::string& txtName = "activity_log.txt", const std::string& jsonName = "events.jsonl") {
        logFile.open(txtName, std::ios::out | std::ios::app);
        jsonFile.open(jsonName, std::ios::out | std::ios::app);

        // Создаем отдельную папку 'proc_logs' для полной изоляции истории запусков
        std::error_code ec;
        fs::create_directories("proc_logs", ec);

        procLogFile.open("proc_logs/launches.txt", std::ios::out | std::ios::app);
        procJsonFile.open("proc_logs/launches.jsonl", std::ios::out | std::ios::app);

        if (logFile.is_open()) {
            std::cout << "[+] EDR Main Log: " << fs::absolute(txtName).string() << '\n';
        }

        if (jsonFile.is_open()) {
            std::cout << "[+] EDR Main JSONL: " << fs::absolute(jsonName).string() << '\n';
        }

        if (procLogFile.is_open() && procJsonFile.is_open()) {
            std::cout << "[+] Isolated Process Logs folder active: " << fs::absolute("proc_logs").string() << '\n';
        }
    }

    static void log(
        const std::string& message,
        bool critical = false,
        const std::string& category = "INFO",
        const std::unordered_map<std::string, std::string>& metadata = {},
        bool consoleOutput = true
    ) {
        std::lock_guard<std::mutex> lock(logMutex);
        const std::string ts = getTimestamp();

        const std::string prefix = critical ? "🚨 [ALERT] " : "";
        const std::string line = "[" + ts + "] " + prefix + message;

        // Определяем, является ли лог обычной рутинной операцией процесса
        bool isProcRoutine = (category == "PROC_LAUNCH" || category == "PROC_EXIT");

        // Выводим в терминал ТОЛЬКО если это не рутинный процесс ИЛИ если это критический алерт
        if (consoleOutput) {
            if (!isProcRoutine || critical) {
                std::cout << line << std::endl;
            }
        }

        // Записываем обычные процессы в изолированную папку proc_logs
        if (isProcRoutine) {
            if (procLogFile.is_open()) {
                procLogFile << line << '\n';
                procLogFile.flush();
            }
        } else {
            // Файловые изменения, DNS и Алёрты пишем в главные логи
            if (logFile.is_open()) {
                logFile << line << '\n';
                logFile.flush();
            }
        }

        // Формирование JSON-строки
        std::stringstream ss;
        ss << "{"
           << "\"timestamp\":\"" << ts << "\","
           << "\"category\":\"" << escapeJson(category) << "\","
           << "\"critical\":" << (critical ? "true" : "false") << ","
           << "\"message\":\"" << escapeJson(message) << "\"";

        for (const auto& [key, value] : metadata) {
            ss << ",\"" << escapeJson(key) << "\":\"" << escapeJson(value) << "\"";
        }
        ss << "}\n";

        // JSON направляем аналогично
        if (isProcRoutine) {
            if (procJsonFile.is_open()) {
                procJsonFile << ss.str();
                procJsonFile.flush();
            }
        } else {
            if (jsonFile.is_open()) {
                jsonFile << ss.str();
                jsonFile.flush();
            }
        }
    }
};

// ============================================================================
// DNS RESOLVER
// ============================================================================

std::string resolveDomain(const std::string& ip) {
    static std::unordered_map<std::string, std::string> cache;
    static std::mutex cacheMutex;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        const auto it = cache.find(ip);
        if (it != cache.end()) {
            return it->second;
        }
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
        return ip;
    }

    char host[NI_MAXHOST]{};

    const int result = getnameinfo(
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address),
        host,
        sizeof(host),
        nullptr,
        0,
        NI_NAMEREQD
    );

    const std::string domain = (result == 0) ? std::string(host) : "direct-ip";

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[ip] = domain;
    }

    return domain;
}

// ============================================================================
// CONFIGURABLE RULES ENGINE & QUARANTINE MANAGER
// ============================================================================

struct Rule {
    std::string name;
    std::string category;
    std::string type;
    std::string pattern;
    std::string action;
};

class RulesEngine {
private:
    static inline std::vector<Rule> rules_;
    static inline std::mutex rulesMutex_;

    static std::string trim(const std::string& str) {
        const size_t first = str.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) return "";
        const size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

public:
    static void createDefaultRulesFile(const std::string& path) {
        if (fs::exists(path)) return;

        std::ofstream file(path);
        if (!file.is_open()) return;

        file << "# EDR Rules Configuration\n"
             << "# Format: RULE_NAME | CATEGORY | TYPE | PATTERN | ACTION\n"
             << "# Actions: alert, kill, quarantine\n\n"
             << "Detect_NC_ReverseShell       | process | cmdline_match     | -e /bin/               | kill\n"
             << "Detect_DevTcp_ReverseShell   | process | cmdline_match     | /dev/tcp/              | kill\n"
             << "Detect_Python_PTY            | process | cmdline_match     | pty.spawn              | kill\n"
             << "Detect_Webshell_Spawn        | process | cmdline_match     | webshell_activity      | kill\n"
             << "Detect_Download_Pipe         | process | cmdline_match     | | bash                 | kill\n"
             << "Detect_Shadow_Access         | process | cmdline_match     | /etc/shadow            | alert\n"
             << "Detect_SUID_Abuse            | process | cmdline_match     | chmod +s               | alert\n"
             << "Detect_AntiForensics_LogWipe | process | cmdline_match     | history -c             | alert\n"
             << "Detect_TempDir_Execution     | process | path_match        | /tmp/                  | quarantine\n"
             << "Detect_DevShm_Execution      | process | path_match        | /dev/shm/              | quarantine\n"
             << "Detect_Yara_Malware          | process | yara_match        | Detect_Test_Malware    | kill\n"
             << "Detect_Cron_Persistence      | file    | persistence_match | /etc/cron              | alert\n"
             << "Detect_Systemd_Persistence   | file    | persistence_match | /etc/systemd/system    | alert\n"
             << "Detect_SSH_Backdoor          | file    | persistence_match | authorized_keys        | alert\n"
             << "Detect_Linker_Hijack         | file    | persistence_match | /etc/ld.so.preload     | alert\n";

        file.close();
        Logger::log("[RULES] Default rules file created: " + path, false, "CONFIG");
    }

    static void loadRules(const std::string& path) {
        std::lock_guard<std::mutex> lock(rulesMutex_);
        rules_.clear();

        createDefaultRulesFile(path);

        std::ifstream file(path);
        if (!file.is_open()) {
            Logger::log("[ERROR] Cannot open rules file: " + path, true, "CONFIG");
            return;
        }

        std::string line;
        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;

            std::stringstream ss(line);
            std::string name, category, type, pattern, action;

            if (std::getline(ss, name, '|') &&
                std::getline(ss, category, '|') &&
                std::getline(ss, type, '|') &&
                std::getline(ss, pattern, '|') &&
                std::getline(ss, action, '|')) {

                Rule rule = {
                    trim(name),
                    trim(category),
                    trim(type),
                    trim(pattern),
                    trim(action)
                };

                std::transform(rule.action.begin(), rule.action.end(), rule.action.begin(), ::tolower);
                rules_.push_back(rule);
            }
        }
        Logger::log("[RULES] Successfully loaded " + std::to_string(rules_.size()) + " security rules from " + path, false, "CONFIG");
    }

    static std::vector<Rule> getRules() {
        std::lock_guard<std::mutex> lock(rulesMutex_);
        return rules_;
    }

    static Rule findRuleForYara(const std::string& yaraRuleName) {
        std::lock_guard<std::mutex> lock(rulesMutex_);
        for (const auto& r : rules_) {
            if (r.type == "yara_match" && r.pattern == yaraRuleName) {
                return r;
            }
        }
        return {"Yara_Default_Block", "process", "yara_match", yaraRuleName, "kill"};
    }
};

class QuarantineManager {
public:
    static inline const std::string QUARANTINE_DIR = "/var/lib/edr/quarantine";

    static bool init() {
        try {
            if (!fs::exists(QUARANTINE_DIR)) {
                fs::create_directories(QUARANTINE_DIR);
                fs::permissions(QUARANTINE_DIR, fs::perms::owner_all);
                Logger::log("[🛡️ QUARANTINE] Isolated directory initialized: " + QUARANTINE_DIR, false, "QUARANTINE");
            }
            return true;
        } catch (const std::exception& e) {
            Logger::log("[ERROR] Cannot initialize quarantine directory: " + std::string(e.what()), true, "QUARANTINE");
            return false;
        }
    }

    static std::string quarantineFile(const std::string& filePath) {
        if (filePath.empty()) return "";

        try {
            fs::path src(filePath);
            std::error_code ec;

            if (!fs::exists(src, ec) || fs::is_directory(src, ec)) {
                return "";
            }

            init();

            auto now = std::chrono::system_clock::now();
            auto duration = now.time_since_epoch();
            std::string timestamp = std::to_string(
                std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
            );

            std::string filename = src.filename().string();
            fs::path dest = fs::path(QUARANTINE_DIR) / (filename + "." + timestamp + ".quarantine");

            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            fs::remove(src);
            fs::permissions(dest, fs::perms::none);

            Logger::log(
                "[🛡️ QUARANTINE] File isolated successfully: " + src.string() + " -> " + dest.string(),
                true,
                "QUARANTINE",
                {{"source_path", src.string()}, {"quarantine_path", dest.string()}}
            );

            return dest.string();
        } catch (const std::exception& e) {
            Logger::log("[ERROR] Failed to quarantine file " + filePath + ": " + e.what(), true, "QUARANTINE");
            return "";
        }
    }
};

// ============================================================================
// MEMORY HUNTER (RWX REGION SCANNER)
// ============================================================================

class MemoryHunter {
public:
    static bool hasRWXRegions(unsigned long pid, std::string& details) {
        details.clear();
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        if (!maps.is_open()) return false;

        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("rwxp") != std::string::npos) {
                details = line;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// PROCESS METADATA & COMMAND LINE PARSER
// ============================================================================

struct ProcessMeta {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string name = "<unknown>";
    std::string exePath;
    std::string cmdline;
};

ProcessMeta getProcessMeta(unsigned long pid) {
    ProcessMeta result;
    result.pid = pid;

    if (pid == 0) {
        return result;
    }

    const std::string pidText = std::to_string(pid);

    std::ifstream statFile("/proc/" + pidText + "/stat");
    if (statFile.is_open()) {
        std::string line;
        std::getline(statFile, line);

        const std::size_t openBracket = line.find('(');
        const std::size_t closeBracket = line.rfind(')');

        if (openBracket != std::string::npos &&
            closeBracket != std::string::npos &&
            closeBracket > openBracket) {

            result.name = line.substr(
                openBracket + 1,
                closeBracket - openBracket - 1
            );

            std::istringstream rest(line.substr(closeBracket + 2));
            char state = 0;
            rest >> state >> result.ppid;
        }
    }

    char exeBuffer[PATH_MAX]{};
    const std::string exeLink = "/proc/" + pidText + "/exe";
    const ssize_t length = readlink(
        exeLink.c_str(),
        exeBuffer,
        sizeof(exeBuffer) - 1
    );

    if (length > 0) {
        exeBuffer[length] = '\0';
        result.exePath = exeBuffer;
    }

    std::ifstream cmdFile("/proc/" + pidText + "/cmdline", std::ios::binary);
    if (cmdFile.is_open()) {
        std::stringstream ss;
        char ch;
        bool hasArgs = false;
        while (cmdFile.get(ch)) {
            if (ch == '\0') {
                ss << ' ';
            } else {
                ss << ch;
            }
            hasArgs = true;
        }
        std::string cmd = ss.str();
        while (!cmd.empty() && cmd.back() == ' ') {
            cmd.pop_back();
        }
        if (hasArgs && !cmd.empty()) {
            result.cmdline = cmd;
        }
    }

    return result;
}

// ============================================================================
// NOISE FILTER
// ============================================================================

bool isProcessNoise(const ProcessMeta& process, const ProcessMeta& parent) {
    if (process.ppid == 2) {
        return true;
    }

    const std::string& name = process.name;
    const std::string& parentName = parent.name;

    static const std::vector<std::string> noiseNames = {
        "kworker", "ksoftirqd", "migration", "cpuhp", "systemd", "dbus", "gnome-shell", "Xorg", "wayland",
        "pulseaudio", "pipewire", "NetworkManager", "gvfsd", "at-spi", "dconf", "cupsd", "dockerd", "containerd",
        "runc", "packagekitd", "fwupd", "tracker-miner-f", "tracker-extract", "polkitd", "udisksd", "colord",
        "accounts-daemon", "thermald", "irqbalance", "rsyslogd", "cron", "anacron", "dnsmasq", "libvirtd",
        "snmpd", "scdaemon", "pcscd", "gpg-agent", "agent", "rtkit-daemon", "upowerd", "wpa_supplicant",
        "nfsd", "rpcbind", "avahi-daemon", "modem-manager", "apparmor", "snapd", "flatpak"
    };

    for (const auto& noise : noiseNames) {
        if (name.rfind(noise, 0) == 0 || parentName.rfind(noise, 0) == 0) {
            return true;
        }
    }

    static const std::vector<std::string> browsers = {
        "firefox", "chrome", "chromium", "msedge", "brave", "opera", "Web Content", "Socket Process", "RDD Process", "Utility Process"
    };
    for (const auto& browser : browsers) {
        if (name.find(browser) != std::string::npos || parentName.find(browser) != std::string::npos) {
            return true;
        }
    }

    if (name == "cpuUsage.sh" || parentName == "cpuUsage.sh") {
        return true;
    }

    if (parentName == "code" || parentName.find("code") != std::string::npos ||
        parentName == "gnome-terminal" || parentName == "tmux" || parentName == "screen" || parentName == "bash") {
        if (name == "sleep" || name == "cat" || name == "grep" || name == "ps" || name == "ls" ||
            name == "sed" || name == "awk" || name == "cut" || name == "tr" || name == "head" ||
            name == "tail" || name == "dirname" || name == "basename" || name == "which" || name == "uname") {
            return true;
        }
    }

    if (name == "node" || name == "python" || name == "python3" || name == "gopls" || name == "pyright" || name == "tsserver") {
        if (process.cmdline.find("extension") != std::string::npos || process.cmdline.find("language") != std::string::npos) {
            return true;
        }
    }

    if (name == "bwrap" || name == "glycin-image-rs" || name == "glycin-svg" || name == "tar" || name == "gzip") {
        return true;
    }

    return false;
}

bool isNetworkNoise(const std::string& name) {
    return name == "systemd-resolved" ||
           name == "avahi-daemon" ||
           name == "kworker" ||
           name.rfind("kworker/", 0) == 0 ||
           name.find("firefox") != std::string::npos ||
           name.find("chrome") != std::string::npos;
}

// ============================================================================
// ACTIVE RESPONDER
// ============================================================================

class ActiveResponder {
public:
    static bool isProtectedProcess(
        unsigned long pid,
        const std::string& name
    ) {
        if (pid <= 1000 || pid == static_cast<unsigned long>(getpid())) {
            return true;
        }

        const std::vector<std::string> protectedNames = {
            "systemd",
            "gdm3",
            "gnome-shell",
            "Xorg",
            "wayland",
            "dbus-daemon",
            "pipewire",
            "pulseaudio",
            "NetworkManager",
            "code",
            "app"
        };

        std::string lowerName = name;
        std::transform(
            lowerName.begin(),
            lowerName.end(),
            lowerName.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            }
        );

        for (const auto& protectedName : protectedNames) {
            std::string lowerProtected = protectedName;
            std::transform(
                lowerProtected.begin(),
                lowerProtected.end(),
                lowerProtected.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                }
            );

            if (lowerName == lowerProtected) {
                return true;
            }
        }

        return false;
    }

    static void terminateProcess(
        unsigned long pid,
        const std::string& name,
        const std::string& reason
    ) {
        if (isProtectedProcess(pid, name)) {
            Logger::log(
                "[WHITELIST] Kill skipped for protected process " +
                name + " (PID: " + std::to_string(pid) + ")",
                false,
                "WHITELIST",
                {{"pid", std::to_string(pid)}, {"process", name}}
            );
            return;
        }

        Logger::log(
            "[RESPONSE] 🛑 Terminating PID: " +
            std::to_string(pid) +
            " (" + name + ") | Reason: " + reason,
            true,
            "RESPONSE",
            {{"pid", std::to_string(pid)}, {"process", name}, {"reason", reason}}
        );

        if (kill(static_cast<pid_t>(pid), SIGKILL) == 0) {
            Logger::log(
                "[RESPONSE] Process PID " +
                std::to_string(pid) +
                " terminated successfully",
                false,
                "RESPONSE"
            );
        } else {
            Logger::log(
                "[ERROR] Cannot terminate PID " +
                std::to_string(pid) + ": " +
                std::strerror(errno),
                true,
                "ERROR"
            );
        }
    }
};

// ============================================================================
// REAL-TIME PROCESS CONNECTOR (NETLINK CN_PROC)
// ============================================================================

class ProcessConnector {
private:
    int nl_sock = -1;
    bool running = false;

public:
    typedef std::function<void(unsigned long pid, bool start)> EventCallback;

    bool init() {
        nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
        if (nl_sock < 0) return false;

        sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = CN_IDX_PROC;
        addr.nl_pid = getpid();

        if (bind(nl_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(nl_sock);
            return false;
        }

        proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
        nlmsghdr nl_hdr{};
        nl_hdr.nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
        nl_hdr.nlmsg_type = NLMSG_DONE;
        nl_hdr.nlmsg_flags = 0;
        nl_hdr.nlmsg_seq = 0;
        nl_hdr.nlmsg_pid = getpid();

        char buf[1024]{};
        std::memcpy(buf, &nl_hdr, sizeof(nl_hdr));

        cn_msg msg{};
        msg.id.idx = CN_IDX_PROC;
        msg.id.val = CN_VAL_PROC;
        msg.len = sizeof(op);

        std::memcpy(buf + sizeof(nl_hdr), &msg, sizeof(msg));
        std::memcpy(buf + sizeof(nl_hdr) + sizeof(msg), &op, sizeof(op));

        return send(nl_sock, buf, nl_hdr.nlmsg_len, 0) >= 0;
    }

    void listen(EventCallback callback) {
        running = true;
        char buf[2048]{};

        while (running) {
            ssize_t len = recv(nl_sock, buf, sizeof(buf), 0);
            if (len <= 0) continue;

            auto* nl_hdr = reinterpret_cast<nlmsghdr*>(buf);
            for (; NLMSG_OK(nl_hdr, len); nl_hdr = NLMSG_NEXT(nl_hdr, len)) {
                if (nl_hdr->nlmsg_type != NLMSG_DONE) continue;

                auto* msg = reinterpret_cast<cn_msg*>(NLMSG_DATA(nl_hdr));
                if (msg->id.idx != CN_IDX_PROC || msg->id.val != CN_VAL_PROC) continue;

                auto* ev = reinterpret_cast<proc_event*>(msg->data);

                if (ev->what == PROC_EVENT_EXEC) {
                    callback(ev->event_data.exec.process_pid, true);
                } else if (ev->what == PROC_EVENT_EXIT) {
                    callback(ev->event_data.exit.process_pid, false);
                }
            }
        }
    }

    void startAsync(EventCallback cb) {
        if (init()) {
            Logger::log("[NETLINK] Real-time Netlink Process Connector active", false, "SYSTEM");
            std::thread(&ProcessConnector::listen, this, cb).detach();
        } else {
            Logger::log("[WARNING] Netlink Connector failed. Using process scanner.", true, "SYSTEM");
        }
    }
};

// ============================================================================
// EMBEDDED DNS WATCHER (PCAP DRIVEN WITH DEDUPLICATION)
// ============================================================================

struct UdpSocketInfo {
    unsigned long inode = 0;
    unsigned int localPort = 0;
};

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

    static std::vector<UdpSocketInfo> readUdpSockets() {
        std::vector<UdpSocketInfo> sockets;
        std::ifstream udpFile("/proc/net/udp");
        if (!udpFile.is_open()) return sockets;

        std::string line;
        std::getline(udpFile, line); // header

        while (std::getline(udpFile, line)) {
            std::istringstream input(line);
            std::string slot, localEndpoint, remoteEndpoint, state;
            input >> slot >> localEndpoint >> remoteEndpoint >> state;

            std::vector<std::string> columns;
            std::string column;
            while (input >> column) columns.push_back(column);

            if (columns.size() < 7) continue;

            const std::size_t separator = localEndpoint.find(':');
            if (separator == std::string::npos) continue;

            unsigned int port = 0;
            unsigned long inode = 0;
            try {
                port = std::stoul(localEndpoint.substr(separator + 1), nullptr, 16);
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

    static std::unordered_map<unsigned long, unsigned long> buildInodeToPidMap(const std::set<unsigned long>& wantedInodes) {
        std::unordered_map<unsigned long, unsigned long> result;
        if (wantedInodes.empty()) return result;

        try {
            for (const auto& processEntry : fs::directory_iterator("/proc")) {
                const std::string pidText = processEntry.path().filename().string();
                if (!isNumeric(pidText)) continue;

                unsigned long pid = 0;
                try { pid = std::stoul(pidText); } catch (...) { continue; }

                const fs::path fdDirectory = processEntry.path() / "fd";
                for (const auto& fdEntry : fs::directory_iterator(fdDirectory, fs::directory_options::skip_permission_denied)) {
                    char linkBuffer[PATH_MAX]{};
                    const ssize_t length = readlink(fdEntry.path().c_str(), linkBuffer, sizeof(linkBuffer) - 1);
                    if (length <= 0) continue;

                    linkBuffer[length] = '\0';
                    const std::string target = linkBuffer;
                    if (target.rfind("socket:[", 0) != 0) continue;

                    const std::size_t end = target.find(']');
                    if (end == std::string::npos) continue;

                    unsigned long inode = 0;
                    try { inode = std::stoul(target.substr(8, end - 8)); } catch (...) { continue; }

                    if (wantedInodes.find(inode) != wantedInodes.end()) {
                        result[inode] = pid;
                    }
                }
            }
        } catch (...) {}

        return result;
    }

    static std::unordered_map<unsigned int, unsigned long> buildPortToPidMap() {
        std::unordered_map<unsigned int, unsigned long> result;
        const auto sockets = readUdpSockets();
        std::set<unsigned long> wantedInodes;
        for (const auto& s : sockets) wantedInodes.insert(s.inode);

        const auto inodeToPid = buildInodeToPidMap(wantedInodes);
        for (const auto& s : sockets) {
            const auto owner = inodeToPid.find(s.inode);
            if (owner != inodeToPid.end()) {
                result[s.localPort] = owner->second;
            }
        }
        return result;
    }

    static bool parseDnsName(const unsigned char* data, std::size_t size, std::size_t offset, std::string& name) {
        name.clear();
        if (data == nullptr || offset >= size) return false;

        std::size_t position = offset;
        bool firstLabel = true;

        while (position < size) {
            const unsigned char labelLength = data[position++];
            if (labelLength == 0) break;

            if ((labelLength & 0xC0) != 0) return false;
            if (labelLength > 63 || position + labelLength > size) return false;

            if (!firstLabel) name += '.';

            for (std::size_t i = 0; i < labelLength; ++i) {
                const unsigned char c = data[position + i];
                if (std::isalnum(c) || c == '-' || c == '_') {
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

    bool alreadySeen(unsigned long pid, const std::string& domain) {
        const std::string key = std::to_string(pid) + "|" + domain;
        const auto now = std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lock(seenMutex_);
        const auto it = seenQueries_.find(key);

        if (it != seenQueries_.end()) {
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (age < 15) return true;
        }

        seenQueries_[key] = now;
        return false;
    }

    void processPacket(const pcap_pkthdr* header, const unsigned char* packet) {
        if (header == nullptr || packet == nullptr) return;

        const int datalink = pcap_datalink(capture_);
        std::size_t networkOffset = 0;

        if (datalink == DLT_EN10MB) networkOffset = 14;
        else if (datalink == DLT_LINUX_SLL) networkOffset = 16;
        else return;

        if (header->caplen < networkOffset + 20) return;

        const unsigned char* ip = packet + networkOffset;
        const unsigned char version = ip[0] >> 4;
        const unsigned char ipHeaderLength = (ip[0] & 0x0F) * 4;

        if (version != 4 || ipHeaderLength < 20 || header->caplen < networkOffset + ipHeaderLength + 8) return;
        if (ip[9] != IPPROTO_UDP) return;

        const unsigned char* udp = ip + ipHeaderLength;
        const unsigned short sourcePort = static_cast<unsigned short>(udp[0] << 8 | udp[1]);
        const unsigned short destinationPort = static_cast<unsigned short>(udp[2] << 8 | udp[3]);

        if (destinationPort != 53) return;

        const std::size_t dnsOffset = networkOffset + ipHeaderLength + 8;
        if (header->caplen < dnsOffset + 12) return;

        const unsigned char* dns = packet + dnsOffset;
        const unsigned short flags = static_cast<unsigned short>(dns[2] << 8 | dns[3]);

        if ((flags & 0x8000) != 0) return;

        const unsigned short questionCount = static_cast<unsigned short>(dns[4] << 8 | dns[5]);
        if (questionCount == 0) return;

        std::string domain;
        if (!parseDnsName(dns, header->caplen - dnsOffset, 12, domain)) return;

        if (domain == "localhost" || endsWith(domain, ".local") || endsWith(domain, ".arpa")) return;

        const auto portToPid = buildPortToPidMap();
        unsigned long pid = 0;
        ProcessMeta process;

        const auto owner = portToPid.find(sourcePort);
        if (owner != portToPid.end()) {
            pid = owner->second;
            process = getProcessMeta(pid);
        }

        if (isProcessNoise(process, getProcessMeta(process.ppid))) return;
        if (alreadySeen(pid, domain)) return;

        std::stringstream message;
        message << "[🌐 DNS_QUERY] App: [" << (process.name == "<unknown>" ? "network-app" : process.name)
                << "] (PID: " << pid << ") -> " << domain;

        Logger::log(
            message.str(),
            false,
            "DNS_QUERY",
            {{"pid", std::to_string(pid)}, {"app", process.name}, {"domain", domain}},
            true
        );
    }

    static void packetCallback(unsigned char* userData, const pcap_pkthdr* header, const unsigned char* packet) {
        auto* watcher = reinterpret_cast<DnsWatcher*>(userData);
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

        if (pcap_findalldevs(&devices, errorBuffer) == -1) {
            Logger::log("[DNS] Cannot list network interfaces: " + std::string(errorBuffer), true, "DNS_ERROR");
            return false;
        }

        pcap_if_t* selected = nullptr;
        for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
            if (!(device->flags & PCAP_IF_LOOPBACK) && device->addresses != nullptr) {
                selected = device;
                break;
            }
        }

        if (selected == nullptr) selected = devices;
        if (selected == nullptr) {
            Logger::log("[DNS] No capture network interface found", true, "DNS_ERROR");
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
            Logger::log("[DNS] Cannot open interface: " + std::string(errorBuffer), true, "DNS_ERROR");
            return false;
        }

        bpf_program filter{};
        const char* filterText = "udp dst port 53";

        if (pcap_compile(capture_, &filter, filterText, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            Logger::log("[DNS] Cannot compile packet filter", true, "DNS_ERROR");
            return false;
        }

        if (pcap_setfilter(capture_, &filter) == -1) {
            pcap_freecode(&filter);
            Logger::log("[DNS] Cannot apply packet filter", true, "DNS_ERROR");
            return false;
        }

        pcap_freecode(&filter);

        Logger::log("[DNS] Embedded DNS Sniffer active on interface: " + interfaceName_, false, "SYSTEM");

        const int result = pcap_loop(
            capture_,
            0,
            &DnsWatcher::packetCallback,
            reinterpret_cast<unsigned char*>(this)
        );

        return result >= 0;
    }

    void startAsync() {
        std::thread([this]() { start(); }).detach();
    }
};

// ============================================================================
// PERSISTENCE WATCHER
// ============================================================================

struct PersistenceAlert {
    std::string techniqueId;
    std::string techniqueName;
    std::string targetDescription;
    std::string filePath;
    std::string eventType;
};

class PersistenceWatcher {
public:
    static bool inspectPath(const fs::path& fullPath, const std::string& eventType, PersistenceAlert& alert) {
        std::string pathStr = fullPath.lexically_normal().string();
        std::string filename = fullPath.filename().string();

        if (pathStr.rfind("/etc/cron", 0) == 0 || 
            pathStr.rfind("/var/spool/cron", 0) == 0 || 
            pathStr == "/etc/crontab") {
            alert = {
                "T1053.003",
                "Scheduled Task/Job: Cron Persistence",
                "Cron configuration or spool directory modified",
                pathStr,
                eventType
            };
            return true;
        }

        if (pathStr.rfind("/etc/systemd/system", 0) == 0 || 
            pathStr.rfind("/lib/systemd/system", 0) == 0 ||
            pathStr.rfind("/usr/lib/systemd/system", 0) == 0 ||
            pathStr.find("/.config/systemd/user") != std::string::npos) {
            
            if (filename.find(".service") != std::string::npos || 
                filename.find(".timer") != std::string::npos ||
                filename.find(".target") != std::string::npos) {
                alert = {
                    "T1543.002",
                    "Create or Modify System Process: Systemd Service",
                    "Systemd unit file added or modified",
                    pathStr,
                    eventType
                };
                return true;
            }
        }

        if (filename == ".bashrc" || filename == ".bash_profile" || filename == ".profile" ||
            filename == ".zshrc" || filename == ".bash_login" || filename == ".bash_logout" ||
            pathStr.rfind("/etc/profile", 0) == 0 || pathStr.rfind("/etc/bash.bashrc", 0) == 0) {
            alert = {
                "T1546.004",
                "Event Triggered Execution: Shell Startup Script",
                "User or global shell profile / startup script modified",
                pathStr,
                eventType
            };
            return true;
        }

        if (pathStr.find("/.ssh/authorized_keys") != std::string::npos ||
            pathStr.find("/.ssh/authorized_keys2") != std::string::npos ||
            pathStr.rfind("/etc/ssh/sshd_config", 0) == 0) {
            alert = {
                "T1098.004",
                "Account Manipulation: SSH Authorized Keys Backdoor",
                "SSH authorized keys or SSH daemon configuration altered",
                pathStr,
                eventType
            };
            return true;
        }

        if (pathStr.find("/autostart/") != std::string::npos ||
            pathStr.rfind("/etc/init.d", 0) == 0 ||
            pathStr.rfind("/etc/rc.local", 0) == 0 ||
            pathStr.rfind("/etc/rc.d", 0) == 0) {
            alert = {
                "T1547.001",
                "Boot or Logon Autostart Execution: init.d / Desktop Autostart",
                "Startup script or GUI autostart desktop entry modified",
                pathStr,
                eventType
            };
            return true;
        }

        if (pathStr == "/etc/ld.so.preload" || pathStr.rfind("/etc/ld.so.conf", 0) == 0) {
            alert = {
                "T1574.006",
                "Hijack Execution Flow: Dynamic Linker Hijacking",
                "Global library preload or dynamic linker configuration altered",
                pathStr,
                eventType
            };
            return true;
        }

        return false;
    }
};

// ============================================================================
// MITRE ATT&CK BEHAVIORAL ANALYZER
// ============================================================================

struct MitreFinding {
    std::string techniqueId;
    std::string techniqueName;
    std::string description;
    bool webShellSignal = false;
};

class MitreAnalyzer {
public:
    static std::vector<MitreFinding> analyze(const ProcessMeta& process, const ProcessMeta& parent) {
        std::vector<MitreFinding> findings;

        std::string cmd = process.cmdline;
        std::string procName = process.name;
        std::string parentName = parent.name;

        std::string lowerCmd = cmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);
        std::string lowerParent = parentName;
        std::transform(lowerParent.begin(), lowerParent.end(), lowerParent.begin(), ::tolower);
        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);

        // 1. Bash /dev/tcp Reverse Shell
        if (lowerCmd.find("/dev/tcp/") != std::string::npos || lowerCmd.find("/dev/udp/") != std::string::npos) {
            findings.push_back({
                "T1059.004",
                "Unix Shell: Reverse Shell via /dev/tcp or /dev/udp",
                "Detected network pipe redirect in command line: " + cmd,
                false
            });
        }

        // 2. Netcat Reverse Shell
        if ((lowerProc == "nc" || lowerProc == "netcat" || lowerProc == "ncat") &&
            (lowerCmd.find("-e ") != std::string::npos || lowerCmd.find("-c ") != std::string::npos || lowerCmd.find("/bin/") != std::string::npos)) {
            findings.push_back({
                "T1059",
                "Command and Scripting Interpreter: Netcat Reverse Shell",
                "Netcat spawned with shell execution flag: " + cmd,
                false
            });
        }

        // 3. Python PTY Reverse Shell
        if (lowerProc.find("python") != std::string::npos) {
            if ((lowerCmd.find("pty.spawn") != std::string::npos || lowerCmd.find("pty") != std::string::npos) &&
                (lowerCmd.find("socket") != std::string::npos || lowerCmd.find("connect") != std::string::npos)) {
                findings.push_back({
                    "T1059.006",
                    "Python: Interactive Reverse Shell PTY Injection",
                    "Python inline script opening socket with PTY shell: " + cmd,
                    false
                });
            }
        }

        // 4. Web Shell Activity
        const std::vector<std::string> webServers = {
            "apache", "apache2", "httpd", "nginx", "lighttpd", "tomcat", "php-fpm", "caddy"
        };
        const std::vector<std::string> shells = {
            "bash", "sh", "dash", "zsh", "python", "python3", "perl", "php", "whoami", "id"
        };

        bool parentIsWeb = false;
        for (const auto& ws : webServers) {
            if (lowerParent.find(ws) != std::string::npos) {
                parentIsWeb = true;
                break;
            }
        }

        if (parentIsWeb) {
            for (const auto& sh : shells) {
                if (lowerProc == sh) {
                    findings.push_back({
                        "T1505.003",
                        "Server Software Component: Web Shell Activity",
                        "Web server [" + parentName + "] spawned shell process [" + procName + "]: " + cmd,
                        true
                    });
                    break;
                }
            }
        }

        // 5. Download & Pipe Exec
        if ((lowerCmd.find("curl") != std::string::npos || lowerCmd.find("wget") != std::string::npos) &&
            (lowerCmd.find("| bash") != std::string::npos || lowerCmd.find("| sh") != std::string::npos || lowerCmd.find("|bash") != std::string::npos || lowerCmd.find("|sh") != std::string::npos)) {
            findings.push_back({
                "T1059",
                "Command and Scripting Interpreter: Download & Pipe to Shell",
                "Detected pipe from web download directly into shell interpreter: " + cmd,
                false
            });
        }

        // 6. Sensitive File Access
        if (lowerCmd.find("/etc/shadow") != std::string::npos || lowerCmd.find("/etc/sudoers") != std::string::npos) {
            findings.push_back({
                "T1087",
                "Account Discovery: Sensitive File Access Attempt",
                "Access to sensitive authentication file detected in command: " + cmd,
                false
            });
        }

        // 7. SUID Bit Abuse
        if (lowerProc == "chmod" && (lowerCmd.find("+s") != std::string::npos || lowerCmd.find("4755") != std::string::npos || lowerCmd.find("4777") != std::string::npos)) {
            findings.push_back({
                "T1548.001",
                "Abuse Elevation Control Mechanism: SUID Bit Modification",
                "Attempt to grant SUID execution bit detected: " + cmd,
                false
            });
        }

        // 8. Log / History Wiping
        if (lowerCmd.find("history -c") != std::string::npos || lowerCmd.find("rm -rf /var/log") != std::string::npos || lowerCmd.find("> /var/log") != std::string::npos) {
            findings.push_back({
                "T1070.004",
                "Indicator Removal: Log / History Wiping Attempt",
                "Anti-forensics activity detected in command line: " + cmd,
                false
            });
        }

        return findings;
    }
};

// ============================================================================
// YARA SCANNER
// ============================================================================

class YaraScanner {
private:
    YR_COMPILER* compiler_ = nullptr;
    YR_RULES* rules_ = nullptr;
    bool initialized_ = false;

    static int callback(
        YR_SCAN_CONTEXT*,
        int message,
        void* messageData,
        void* userData
    ) {
        if (message == CALLBACK_MSG_RULE_MATCHING &&
            messageData != nullptr &&
            userData != nullptr) {

            auto* rule = static_cast<YR_RULE*>(messageData);
            auto* ruleName = static_cast<std::string*>(userData);
            *ruleName = rule->identifier;
        }

        return CALLBACK_CONTINUE;
    }

public:
    YaraScanner() {
        if (yr_initialize() != ERROR_SUCCESS) {
            Logger::log("[YARA] Initialization failed", true, "YARA_ERROR");
            return;
        }

        if (yr_compiler_create(&compiler_) != ERROR_SUCCESS || compiler_ == nullptr) {
            Logger::log("[YARA] Compiler creation failed", true, "YARA_ERROR");
            yr_finalize();
            return;
        }

        const char* ruleText = R"(
rule Detect_Test_Malware {
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $custom = "CUSTOM_MALWARE_SIGNATURE_TEST"
    condition:
        any of them
}
)";

        if (yr_compiler_add_string(compiler_, ruleText, nullptr) != ERROR_SUCCESS) {
            Logger::log("[YARA] Rule compilation failed", true, "YARA_ERROR");
            yr_compiler_destroy(compiler_);
            compiler_ = nullptr;
            yr_finalize();
            return;
        }

        if (yr_compiler_get_rules(compiler_, &rules_) != ERROR_SUCCESS || rules_ == nullptr) {
            Logger::log("[YARA] Cannot obtain compiled rules", true, "YARA_ERROR");
            yr_compiler_destroy(compiler_);
            compiler_ = nullptr;
            yr_finalize();
            return;
        }

        initialized_ = true;
        Logger::log("[YARA] Scanner initialized successfully", false, "SYSTEM");
    }

    ~YaraScanner() {
        if (rules_ != nullptr) yr_rules_destroy(rules_);
        if (compiler_ != nullptr) yr_compiler_destroy(compiler_);
        yr_finalize();
    }

    bool scanFile(const std::string& path, std::string& matchedRule) const {
        matchedRule.clear();

        if (!initialized_ || rules_ == nullptr || path.empty()) {
            return false;
        }

        std::error_code error;
        if (!fs::exists(path, error) || !fs::is_regular_file(path, error)) {
            return false;
        }

        const int result = yr_rules_scan_file(
            rules_,
            path.c_str(),
            0,
            callback,
            &matchedRule,
            0
        );

        if (result != ERROR_SUCCESS) {
            return false;
        }

        return !matchedRule.empty();
    }
};

// ============================================================================
// PROCESS WATCHER (PROCESS ANALYSIS ENGINE)
// ============================================================================

class ProcessWatcher {
private:
    std::unordered_map<unsigned long, std::string> knownProcesses_;
    YaraScanner yara_;

    void inspectSingleProcess(unsigned long pid) {
        const ProcessMeta process = getProcessMeta(pid);
        if (process.name == "<unknown>" || process.pid == static_cast<unsigned long>(getpid())) {
            return;
        }

        const ProcessMeta parent = getProcessMeta(process.ppid);

        if (isProcessNoise(process, parent)) {
            return;
        }

        // 1. RWX Memory Scan
        std::string memDetails;
        if (MemoryHunter::hasRWXRegions(pid, memDetails)) {
            std::stringstream alertMsg;
            alertMsg << "\n🧠 [RWX MEMORY DETECTED] Executable & Writable Memory Region Found!\n"
                     << "  ├─ 🎯 Target PID : " << process.pid << " [" << process.name << "]\n"
                     << "  ├─ 📁 Binary Path: " << process.exePath << "\n"
                     << "  └─ 📝 Region Info: " << memDetails;

            Logger::log(
                alertMsg.str(),
                true,
                "MEMORY_HUNTER",
                {{"pid", std::to_string(process.pid)}, {"app", process.name}, {"region", memDetails}}
            );
        }

        // 2. MITRE ATT&CK Behavioral Inspection
        auto findings = MitreAnalyzer::analyze(process, parent);
        bool blockApplied = false;

        for (const auto& finding : findings) {
            std::string targetPattern = finding.techniqueId;
            if (finding.webShellSignal) {
                targetPattern = "webshell_activity";
            }

            std::string action = "alert";
            std::string ruleName = "Behavioral_Analyzer_Alert";

            for (const auto& rule : RulesEngine::getRules()) {
                if (rule.category == "process" &&
                    (rule.type == "cmdline_match" || rule.type == "yara_match") &&
                    (finding.description.find(rule.pattern) != std::string::npos ||
                     targetPattern == rule.pattern)) {
                    action = rule.action;
                    ruleName = rule.name;
                    break;
                }
            }

            std::stringstream alertMsg;
            alertMsg << "\n⚠️  [RULE TRIGGERED] (" << ruleName << ") | MITRE: " << finding.techniqueId << "\n"
                     << "  ├─ 🎯 Process    : [" << process.name << "] (PID: " << process.pid << ")\n"
                     << "  ├─ 👨‍👦 Parent     : [" << parent.name << "] (PID: " << process.ppid << ")\n"
                     << "  ├─ 📝 Details    : " << finding.description << "\n"
                     << "  └─ 🛡️  Response   : " << action;

            Logger::log(
                alertMsg.str(),
                true,
                "MITRE_ATTACK",
                {
                    {"rule_name", ruleName},
                    {"technique_id", finding.techniqueId},
                    {"pid", std::to_string(process.pid)},
                    {"process", process.name},
                    {"cmdline", process.cmdline},
                    {"action", action}
                }
            );

            if (action == "kill" || action == "quarantine") {
                if (action == "quarantine" && !process.exePath.empty()) {
                    ActiveResponder::terminateProcess(process.pid, process.name, "Quarantining process binary");
                    QuarantineManager::quarantineFile(process.exePath);
                } else {
                    ActiveResponder::terminateProcess(process.pid, process.name, "MITRE Behavioral Signature matched: " + finding.techniqueId);
                }
                blockApplied = true;
            }
        }

        if (blockApplied) return;

        // 3. YARA Signature Scan
        std::string matchedYaraRule;
        if (!process.exePath.empty() && yara_.scanFile(process.exePath, matchedYaraRule)) {
            Rule rule = RulesEngine::findRuleForYara(matchedYaraRule);

            std::stringstream alertMsg;
            alertMsg << "\n⚠️  [RULE TRIGGERED] (" << rule.name << ")\n"
                     << "  ├─ 🎯 Process    : [" << process.name << "] (PID: " << process.pid << ")\n"
                     << "  ├─ 📁 Binary Path: " << process.exePath << "\n"
                     << "  ├─ 📝 Yara Match : " << matchedYaraRule << "\n"
                     << "  └─ 🛡️  Response   : " << rule.action;

            Logger::log(
                alertMsg.str(),
                true,
                "YARA_MATCH",
                {{"rule", rule.name}, {"pid", std::to_string(process.pid)}, {"yara_rule", matchedYaraRule}}
            );

            if (rule.action == "kill" || rule.action == "quarantine") {
                if (rule.action == "quarantine") {
                    ActiveResponder::terminateProcess(process.pid, process.name, "Quarantining process binary due to YARA match");
                    QuarantineManager::quarantineFile(process.exePath);
                } else {
                    ActiveResponder::terminateProcess(process.pid, process.name, "YARA Signature matched: " + matchedYaraRule);
                }
                return;
            }
        }

        // 4. Prohibited Path Match (/tmp, /dev/shm)
        bool pathBlocked = false;
        for (const auto& rule : RulesEngine::getRules()) {
            if (rule.category == "process" && rule.type == "path_match") {
                if (!process.exePath.empty() && process.exePath.rfind(rule.pattern, 0) == 0) {
                    std::stringstream alertMsg;
                    alertMsg << "\n⚠️  [RULE TRIGGERED] (" << rule.name << ")\n"
                             << "  ├─ 🎯 Process    : [" << process.name << "] (PID: " << process.pid << ")\n"
                             << "  ├─ 📁 Binary Path: " << process.exePath << "\n"
                             << "  ├─ 📝 Reason      : Executable started from prohibited directory: " << rule.pattern << "\n"
                             << "  └─ 🛡️  Response   : " << rule.action;

                    Logger::log(
                        alertMsg.str(),
                        true,
                        "PATH_MATCH",
                        {{"rule", rule.name}, {"pid", std::to_string(process.pid)}, {"path", process.exePath}}
                    );

                    if (rule.action == "kill" || rule.action == "quarantine") {
                        if (rule.action == "quarantine") {
                            ActiveResponder::terminateProcess(process.pid, process.name, "Quarantining executable from prohibited path");
                            QuarantineManager::quarantineFile(process.exePath);
                        } else {
                            ActiveResponder::terminateProcess(process.pid, process.name, "Execution from prohibited path: " + rule.pattern);
                        }
                        pathBlocked = true;
                        break;
                    }
                }
            }
        }

        if (pathBlocked) return;

        // Нормальные запуски процессов будут тихо лететь в 'proc_logs/launches.txt'
        std::stringstream message;
        message << "[⚙️ PROC_LAUNCH] Process: [" << process.name << "] (PID: " << process.pid << ")"
                << " | Parent: [" << parent.name << "] | Cmd: " << (process.cmdline.empty() ? process.name : process.cmdline);

        Logger::log(
            message.str(),
            false,
            "PROC_LAUNCH",
            {
                {"pid", std::to_string(process.pid)},
                {"ppid", std::to_string(process.ppid)},
                {"process", process.name},
                {"parent", parent.name},
                {"exe", process.exePath},
                {"cmdline", process.cmdline}
            },
            true // Будет записан исключительно в 'proc_logs/launches.*' благодаря логике Logger!
        );
    }

public:
    void handleEvent(unsigned long pid, bool start) {
        if (start) {
            inspectSingleProcess(pid);
        } else {
            Logger::log(
                "[🛑 PROC_EXIT] PID: " + std::to_string(pid),
                false,
                "PROC_EXIT",
                {{"pid", std::to_string(pid)}},
                false
            );
        }
    }

    void scanBaseline() {
        try {
            for (const auto& entry : fs::directory_iterator("/proc")) {
                const std::string pidText = entry.path().filename().string();
                if (!isNumeric(pidText)) continue;

                unsigned long pid = 0;
                try { pid = std::stoul(pidText); } catch (...) { continue; }

                const ProcessMeta process = getProcessMeta(pid);
                if (process.name != "<unknown>") {
                    knownProcesses_[pid] = process.name;
                }
            }
        } catch (...) {}
    }
};

// ============================================================================
// NETWORK WATCHER
// ============================================================================

struct SocketConnection {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string processName;
    std::string exePath;
    std::string remoteIp;
    int remotePort = 0;
    std::string domain;

    std::string key() const {
        return std::to_string(pid) + "|" +
               remoteIp + ":" +
               std::to_string(remotePort);
    }
};

class NetworkWatcher {
private:
    std::unordered_map<std::string, SocketConnection> knownConnections_;

    struct RawSocket {
        unsigned long inode = 0;
        std::string remoteIp;
        int remotePort = 0;
    };

    static bool parseEndpoint(const std::string& endpoint, unsigned int& ip, unsigned int& port) {
        const std::size_t separator = endpoint.find(':');
        if (separator == std::string::npos) return false;

        try {
            ip = std::stoul(endpoint.substr(0, separator), nullptr, 16);
            port = std::stoul(endpoint.substr(separator + 1), nullptr, 16);
        } catch (...) {
            return false;
        }
        return true;
    }

    static std::string procHexToIpv4(unsigned int value) {
        in_addr address{};
        address.s_addr = htonl(value);
        char buffer[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
            return "unknown";
        }
        return buffer;
    }

    static std::unordered_map<unsigned long, unsigned long> buildInodePidMap(const std::set<unsigned long>& wantedInodes) {
        std::unordered_map<unsigned long, unsigned long> result;
        if (wantedInodes.empty()) return result;

        try {
            for (const auto& processEntry : fs::directory_iterator("/proc")) {
                const std::string pidText = processEntry.path().filename().string();
                if (!isNumeric(pidText)) continue;

                unsigned long pid = 0;
                try { pid = std::stoul(pidText); } catch (...) { continue; }

                const fs::path fdDirectory = processEntry.path() / "fd";
                for (const auto& fdEntry : fs::directory_iterator(fdDirectory, fs::directory_options::skip_permission_denied)) {
                    char socketBuffer[PATH_MAX]{};
                    const ssize_t length = readlink(fdEntry.path().c_str(), socketBuffer, sizeof(socketBuffer) - 1);
                    if (length <= 0) continue;

                    socketBuffer[length] = '\0';
                    const std::string target = socketBuffer;
                    if (target.rfind("socket:[", 0) != 0) continue;

                    const std::size_t end = target.find(']');
                    if (end == std::string::npos) continue;

                    unsigned long inode = 0;
                    try { inode = std::stoul(target.substr(8, end - 8)); } catch (...) { continue; }

                    if (wantedInodes.find(inode) != wantedInodes.end()) {
                        result[inode] = pid;
                    }
                }
            }
        } catch (...) {}

        return result;
    }

public:
    void scan() {
        std::vector<RawSocket> rawSockets;
        std::set<unsigned long> wantedInodes;

        std::ifstream tcpFile("/proc/net/tcp");
        if (!tcpFile.is_open()) return;

        std::string line;
        std::getline(tcpFile, line);

        while (std::getline(tcpFile, line)) {
            std::istringstream input(line);
            std::string slot, localEndpoint, remoteEndpoint, state;
            input >> slot >> localEndpoint >> remoteEndpoint >> state;

            if (state != "01") continue;

            std::vector<std::string> columns;
            std::string column;
            while (input >> column) columns.push_back(column);

            if (columns.size() < 7) continue;

            unsigned int remoteIpHex = 0, remotePortHex = 0;
            if (!parseEndpoint(remoteEndpoint, remoteIpHex, remotePortHex)) continue;

            unsigned long inode = 0;
            try { inode = std::stoul(columns[6]); } catch (...) { continue; }

            if (remoteIpHex == 0 || remotePortHex == 0 || inode == 0) continue;

            rawSockets.push_back({
                inode,
                procHexToIpv4(remoteIpHex),
                static_cast<int>(remotePortHex)
            });

            wantedInodes.insert(inode);
        }

        const auto inodeToPid = buildInodePidMap(wantedInodes);
        std::unordered_map<std::string, SocketConnection> currentConnections;

        for (const auto& raw : rawSockets) {
            const auto owner = inodeToPid.find(raw.inode);
            if (owner == inodeToPid.end()) continue;

            const unsigned long pid = owner->second;
            const ProcessMeta process = getProcessMeta(pid);

            if (process.name == "<unknown>" || isNetworkNoise(process.name)) continue;

            SocketConnection connection;
            connection.pid = pid;
            connection.ppid = process.ppid;
            connection.processName = process.name;
            connection.exePath = process.exePath;
            connection.remoteIp = raw.remoteIp;
            connection.remotePort = raw.remotePort;
            connection.domain = resolveDomain(raw.remoteIp);

            currentConnections[connection.key()] = connection;
        }

        for (const auto& [key, connection] : currentConnections) {
            if (knownConnections_.find(key) == knownConnections_.end()) {
                std::stringstream message;
                message << "[🌐 WEB_CONNECT] App: [" << connection.processName
                        << "] (PID: " << connection.pid << ")"
                        << " -> " << connection.remoteIp << ":" << connection.remotePort
                        << " (Domain: " << connection.domain << ")";

                Logger::log(
                    message.str(),
                    false,
                    "WEB_CONNECT",
                    {
                        {"pid", std::to_string(connection.pid)},
                        {"app", connection.processName},
                        {"ip", connection.remoteIp},
                        {"port", std::to_string(connection.remotePort)},
                        {"domain", connection.domain}
                    },
                    true
                );
            }
        }

        for (const auto& [key, connection] : knownConnections_) {
            if (currentConnections.find(key) == currentConnections.end()) {
                std::stringstream message;
                message << "[🌐 WEB_DISCONN] App: [" << connection.processName
                        << "] (PID: " << connection.pid << ")"
                        << " closed connection to " << connection.remoteIp
                        << ":" << connection.remotePort;

                Logger::log(
                    message.str(),
                    false,
                    "WEB_DISCONN",
                    {
                        {"pid", std::to_string(connection.pid)},
                        {"app", connection.processName},
                        {"ip", connection.remoteIp},
                        {"port", std::to_string(connection.remotePort)}
                    },
                    false
                );
            }
        }

        knownConnections_ = std::move(currentConnections);
    }
};

// ============================================================================
// SYSTEM-WIDE RECURSIVE FILE SYSTEM & PERSISTENCE WATCHER (SMART DEDUPLICATOR)
// ============================================================================

class EventFileSystemWatcher {
private:
    int inotifyFd_ = -1;
    std::unordered_map<int, std::string> watches_;
    std::mutex mutex_;

    std::mutex eventCacheMutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> recentFileEvents_;

    bool isDuplicateFileEvent(const std::string& path, const std::string& eventType) {
        std::lock_guard<std::mutex> lock(eventCacheMutex_);
        const std::string key = eventType + "|" + path;
        const auto now = std::chrono::steady_clock::now();

        auto it = recentFileEvents_.find(key);
        if (it != recentFileEvents_.end()) {
            auto elapsedSec = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsedSec < 5) {
                return true;
            }
        }

        recentFileEvents_[key] = now;
        return false;
    }

    bool isExcluded(const fs::path& path) const {
        const std::string normalized = path.lexically_normal().string();

        static const std::vector<std::string> excludedDirs = {
            "/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containers",
            "/var/cache", "/var/log", "/var/tmp", ".cache", ".git", ".vscode", "node_modules",
            "__pycache__", ".cargo", ".npm", ".gnupg", ".config", "proc_logs"
        };

        for (const auto& exc : excludedDirs) {
            if (normalized == exc ||
                normalized.find("/" + exc + "/") != std::string::npos ||
                normalized.rfind(exc + "/", 0) == 0) {
                return true;
            }
        }

        std::string filename = path.filename().string();
        if (filename == "activity_log.txt" || filename == "events.jsonl" || filename == "rules.conf" ||
            endsWith(filename, ".tmp") || endsWith(filename, ".swp") || endsWith(filename, ".swx") ||
            endsWith(filename, "~") || endsWith(filename, ".log") || endsWith(filename, ".lock") ||
            endsWith(filename, ".pyc") || endsWith(filename, ".o")) {
            return true;
        }

        return false;
    }

    void addWatch(const fs::path& directory) {
        if (isExcluded(directory)) return;

        const int watchDescriptor = inotify_add_watch(
            inotifyFd_,
            directory.c_str(),
            IN_CREATE | IN_MODIFY | IN_DELETE | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO
        );

        if (watchDescriptor < 0) return;

        std::lock_guard<std::mutex> lock(mutex_);
        watches_[watchDescriptor] = directory.string();
    }

    void addRecursiveWatches() {
        static const std::vector<std::string> watchRoots = {
            "/etc", "/home", "/root", "/tmp", "/opt", "/var/www"
        };

        for (const auto& r : watchRoots) {
            try {
                if (fs::exists(r) && fs::is_directory(r)) {
                    addWatch(r);
                    for (const auto& entry : fs::recursive_directory_iterator(
                             r, fs::directory_options::skip_permission_denied)) {
                        if (entry.is_directory() && !isExcluded(entry.path())) {
                            addWatch(entry.path());
                        }
                    }
                }
            } catch (...) {}
        }
    }

    void linuxWatchLoop() {
        inotifyFd_ = inotify_init1(IN_NONBLOCK);

        if (inotifyFd_ < 0) {
            Logger::log("[FILE] inotify initialization failed", true, "FILE_ERROR");
            return;
        }

        Logger::log("[FILE] Indexing user & system directories (/etc, /home, /tmp, etc.)...", false, "SYSTEM");
        addRecursiveWatches();
        Logger::log("[FILE] Deduplicated FIM active. Log files protected from bloat.", false, "SYSTEM");

        std::vector<char> buffer(65536);

        while (true) {
            const ssize_t length = read(inotifyFd_, buffer.data(), buffer.size());

            if (length < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(150));
                    continue;
                }
                if (errno == EINTR) continue;
                break;
            }

            ssize_t offset = 0;

            while (offset < length) {
                const auto* event = reinterpret_cast<const struct inotify_event*>(buffer.data() + offset);

                std::string directory;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    const auto it = watches_.find(event->wd);
                    if (it != watches_.end()) {
                        directory = it->second;
                    }
                }

                if (!directory.empty() && event->len > 0) {
                    const fs::path path = fs::path(directory) / event->name;

                    if (!isExcluded(path)) {
                        const bool isDir = (event->mask & IN_ISDIR) != 0;
                        std::string eventType;

                        if (event->mask & IN_CREATE) {
                            eventType = isDir ? "DIRECTORY_CREATED" : "FILE_CREATED";
                            if (isDir) addWatch(path);
                        } else if (event->mask & IN_MODIFY) {
                            eventType = isDir ? "DIRECTORY_MODIFIED" : "FILE_MODIFIED";
                        } else if (event->mask & IN_CLOSE_WRITE) {
                            eventType = "FILE_SAVED";
                        } else if (event->mask & IN_DELETE) {
                            eventType = isDir ? "DIRECTORY_DELETED" : "FILE_DELETED";
                        } else if (event->mask & IN_MOVED_FROM) {
                            eventType = isDir ? "DIRECTORY_MOVED_FROM" : "FILE_MOVED_FROM";
                        } else if (event->mask & IN_MOVED_TO) {
                            eventType = isDir ? "DIRECTORY_MOVED_TO" : "FILE_MOVED_TO";
                            if (isDir) addWatch(path);
                        }

                        if (!eventType.empty()) {
                            PersistenceAlert pAlert;
                            if (PersistenceWatcher::inspectPath(path, eventType, pAlert)) {
                                std::string action = "alert";
                                std::string ruleName = "Persistence_Watcher_Alert";

                                for (const auto& rule : RulesEngine::getRules()) {
                                    if (rule.category == "file" && rule.type == "persistence_match") {
                                        if (path.string().find(rule.pattern) != std::string::npos) {
                                            action = rule.action;
                                            ruleName = rule.name;
                                            break;
                                        }
                                    }
                                }

                                std::stringstream alertMsg;
                                alertMsg << "\n📌 [RULE TRIGGERED] (" << ruleName << ") | MITRE: " << pAlert.techniqueId << "\n"
                                         << "  ├─ 🎯 Modified Path: " << pAlert.filePath << "\n"
                                         << "  ├─ ⚡ Event Type   : " << pAlert.eventType << "\n"
                                         << "  ├─ 📝 Details      : " << pAlert.targetDescription << "\n"
                                         << "  └─ 🛡️  Response     : " << action;

                                Logger::log(
                                    alertMsg.str(),
                                    true,
                                    "PERSISTENCE",
                                    {
                                        {"rule_name", ruleName},
                                        {"technique_id", pAlert.techniqueId},
                                        {"path", pAlert.filePath},
                                        {"action", action}
                                    },
                                    true
                                );

                                if (action == "quarantine") {
                                    QuarantineManager::quarantineFile(path.string());
                                }
                            } else {
                                if (!isDuplicateFileEvent(path.string(), eventType)) {
                                    std::string icon = "📄";
                                    if (eventType.find("DIRECTORY") != std::string::npos) icon = "📁";
                                    else if (eventType == "FILE_SAVED") icon = "💾";
                                    else if (eventType.find("DELETED") != std::string::npos) icon = "🗑️";
                                    else if (eventType.find("MODIFIED") != std::string::npos) icon = "✏️";

                                    Logger::log(
                                        "[" + icon + " " + eventType + "] " + path.string(),
                                        false,
                                        "FILE_WATCH",
                                        {{"event", eventType}, {"path", path.string()}},
                                        true
                                    );
                                }
                            }
                        }
                    }
                }

                offset += sizeof(struct inotify_event) + event->len;
            }
        }

        close(inotifyFd_);
    }

public:
    void startAsync() {
        std::thread(&EventFileSystemWatcher::linuxWatchLoop, this).detach();
    }
};

// ============================================================================
// MAIN
// ============================================================================

int main() {
    Logger::init("activity_log.txt", "events.jsonl");

    Logger::log("==========================================================", false, "SYSTEM");
    Logger::log("   COMMERCIAL-GRADE EDR (With Isolated Process Logs)", false, "SYSTEM");
    Logger::log("==========================================================", false, "SYSTEM");

    RulesEngine::loadRules("rules.conf");
    QuarantineManager::init();

    EventFileSystemWatcher fileWatcher;
    fileWatcher.startAsync();

    DnsWatcher dnsWatcher;
    dnsWatcher.startAsync();

    ProcessWatcher processWatcher;
    processWatcher.scanBaseline();

    NetworkWatcher networkWatcher;

    ProcessConnector connector;
    connector.startAsync([&processWatcher](unsigned long pid, bool start) {
        processWatcher.handleEvent(pid, start);
    });

    Logger::log("[SYSTEM] EDR active! Spills launches into folder 'proc_logs/'.", false, "SYSTEM");
    Logger::log("[SYSTEM] Main terminal prints: Red Alerts + File Ops + Web/DNS queries.\n", false, "SYSTEM");

    while (true) {
        networkWatcher.scan();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return 0;
}
