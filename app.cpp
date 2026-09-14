#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <mutex>
#include <netdb.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <csignal>

#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

#include <yara.h>

namespace fs = std::filesystem;

// ============================================================================
// LOGGER
// ============================================================================

class Logger {
private:
    static inline std::mutex logMutex;
    static inline std::ofstream logFile;

public:
    static void init(const std::string& filename = "activity_log.txt") {
        logFile.open(filename, std::ios::out | std::ios::app);

        if (!logFile.is_open()) {
            std::cerr << "[-] Cannot open log file: " << filename << '\n';
        } else {
            std::cout << "[+] Logging to: "
                      << fs::absolute(filename).string()
                      << '\n';
        }
    }

    static void log(const std::string& message, bool critical = false) {
        std::lock_guard<std::mutex> lock(logMutex);

        const std::string prefix = critical ? "[!] " : "";
        const std::string line = prefix + message;

        std::cout << line << std::endl;

        if (logFile.is_open()) {
            logFile << line << '\n';
            logFile.flush();
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

    const std::string domain =
        result == 0 ? std::string(host) : "direct-ip";

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[ip] = domain;
    }

    return domain;
}

// ============================================================================
// PROCESS METADATA
// ============================================================================

struct ProcessMeta {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string name = "<unknown>";
    std::string exePath;
};

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

ProcessMeta getProcessMeta(unsigned long pid) {
    ProcessMeta result;
    result.pid = pid;

    if (pid == 0) {
        return result;
    }

    const std::string pidText = std::to_string(pid);

    // Надежный разбор /proc/PID/stat.
    std::ifstream statFile(
        "/proc/" + pidText + "/stat"
    );

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

            std::istringstream rest(
                line.substr(closeBracket + 2)
            );

            char state = 0;
            rest >> state >> result.ppid;
        }
    }

    char exeBuffer[PATH_MAX]{};

    const std::string exeLink =
        "/proc/" + pidText + "/exe";

    const ssize_t length = readlink(
        exeLink.c_str(),
        exeBuffer,
        sizeof(exeBuffer) - 1
    );

    if (length > 0) {
        exeBuffer[length] = '\0';
        result.exePath = exeBuffer;
    }

    return result;
}

// ============================================================================
// NOISE FILTER
// ============================================================================

bool isProcessNoise(const ProcessMeta& process) {
    if (process.ppid == 2) {
        return true;
    }

    const std::string& name = process.name;

    if (name.rfind("kworker", 0) == 0 ||
        name.rfind("ksoftirqd", 0) == 0 ||
        name.rfind("migration", 0) == 0 ||
        name.rfind("cpuhp", 0) == 0) {
        return true;
    }

    if (name == "cpuUsage.sh" ||
        name == "bwrap" ||
        name == "glycin-image-rs" ||
        name == "glycin-svg") {
        return true;
    }

    return false;
}

bool isNetworkNoise(const std::string& name) {
    return name == "systemd-resolved" ||
           name == "avahi-daemon" ||
           name == "kworker" ||
           name.rfind("kworker/", 0) == 0;
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
            "NetworkManager"
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
                name + " (PID: " + std::to_string(pid) + ")"
            );
            return;
        }

        Logger::log(
            "[RESPONSE] Terminating PID: " +
            std::to_string(pid) +
            " (" + name + ") | Reason: " + reason,
            true
        );

        if (kill(static_cast<pid_t>(pid), SIGKILL) == 0) {
            Logger::log(
                "[RESPONSE] Process PID " +
                std::to_string(pid) +
                " terminated"
            );
        } else {
            Logger::log(
                "[ERROR] Cannot terminate PID " +
                std::to_string(pid) + ": " +
                std::strerror(errno),
                true
            );
        }
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
            Logger::log("[YARA] Initialization failed", true);
            return;
        }

        if (yr_compiler_create(&compiler_) != ERROR_SUCCESS ||
            compiler_ == nullptr) {
            Logger::log("[YARA] Compiler creation failed", true);
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

        if (yr_compiler_add_string(
                compiler_,
                ruleText,
                nullptr
            ) != ERROR_SUCCESS) {

            Logger::log("[YARA] Rule compilation failed", true);
            yr_compiler_destroy(compiler_);
            compiler_ = nullptr;
            yr_finalize();
            return;
        }

        if (yr_compiler_get_rules(
                compiler_,
                &rules_
            ) != ERROR_SUCCESS ||
            rules_ == nullptr) {

            Logger::log(
                "[YARA] Cannot obtain compiled rules",
                true
            );
            yr_compiler_destroy(compiler_);
            compiler_ = nullptr;
            yr_finalize();
            return;
        }

        initialized_ = true;
        Logger::log("[YARA] Scanner initialized");
    }

    ~YaraScanner() {
        if (rules_ != nullptr) {
            yr_rules_destroy(rules_);
        }

        if (compiler_ != nullptr) {
            yr_compiler_destroy(compiler_);
        }

        yr_finalize();
    }

    bool scanFile(
        const std::string& path,
        std::string& matchedRule
    ) const {
        matchedRule.clear();

        if (!initialized_ || rules_ == nullptr || path.empty()) {
            return false;
        }

        std::error_code error;

        if (!fs::exists(path, error) ||
            !fs::is_regular_file(path, error)) {
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
            Logger::log(
                "[YARA] Scan failed for: " + path,
                true
            );
            return false;
        }

        return !matchedRule.empty();
    }
};

// ============================================================================
// PROCESS WATCHER
// ============================================================================

class ProcessWatcher {
private:
    std::unordered_map<
        unsigned long,
        std::string
    > knownProcesses_;

    YaraScanner yara_;
    bool firstScan_ = true;

public:
    void scan() {
        std::unordered_map<
            unsigned long,
            std::string
        > currentProcesses;

        try {
            for (const auto& entry :
                 fs::directory_iterator("/proc")) {

                const std::string pidText =
                    entry.path().filename().string();

                if (!isNumeric(pidText)) {
                    continue;
                }

                unsigned long pid = 0;

                try {
                    pid = std::stoul(pidText);
                } catch (...) {
                    continue;
                }

                const ProcessMeta process =
                    getProcessMeta(pid);

                if (process.name == "<unknown>") {
                    continue;
                }

                currentProcesses[pid] = process.name;

                if (firstScan_) {
                    continue;
                }

                if (knownProcesses_.find(pid) !=
                    knownProcesses_.end()) {
                    continue;
                }

                if (isProcessNoise(process)) {
                    continue;
                }

                const ProcessMeta parent =
                    getProcessMeta(process.ppid);

                std::stringstream message;
                message << "[PROC_LAUNCH] PID: "
                        << process.pid
                        << " | PPID: "
                        << process.ppid
                        << " | Parent: ["
                        << parent.name
                        << "] | App: ["
                        << process.name
                        << "]";

                Logger::log(message.str());

                // YARA-проверка нового исполняемого файла.
                std::string matchedRule;

                if (yara_.scanFile(
                        process.exePath,
                        matchedRule
                    )) {

                    ActiveResponder::terminateProcess(
                        process.pid,
                        process.name,
                        "YARA rule matched: " + matchedRule
                    );

                    continue;
                }

                // Проверка запуска из временных директорий.
                if (!process.exePath.empty() &&
                    (process.exePath.rfind("/tmp/", 0) == 0 ||
                     process.exePath.rfind("/dev/shm/", 0) == 0)) {

                    ActiveResponder::terminateProcess(
                        process.pid,
                        process.name,
                        "Executable started from temporary directory: " +
                        process.exePath
                    );
                }
            }
        } catch (const std::exception& error) {
            Logger::log(
                std::string("[PROCESS] Scan error: ") +
                error.what(),
                true
            );
        }

        if (!firstScan_) {
            for (const auto& [pid, name] :
                 knownProcesses_) {

                if (currentProcesses.find(pid) ==
                    currentProcesses.end()) {

                    if (name.rfind("kworker", 0) == 0 ||
                        name.rfind("ksoftirqd", 0) == 0 ||
                        name == "cpuUsage.sh" ||
                        name == "bwrap" ||
                        name == "glycin-image-rs" ||
                        name == "glycin-svg") {
                        continue;
                    }

                    Logger::log(
                        "[PROC_EXIT] PID: " +
                        std::to_string(pid) +
                        " | App: [" +
                        name +
                        "]"
                    );
                }
            }
        }

        knownProcesses_ =
            std::move(currentProcesses);

        firstScan_ = false;
    }
};

// ============================================================================
// NETWORK WATCHER
// ============================================================================

struct SocketConnection {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string processName;
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
    std::unordered_map<
        std::string,
        SocketConnection
    > knownConnections_;

    struct RawSocket {
        unsigned long inode = 0;
        std::string remoteIp;
        int remotePort = 0;
    };

    static bool parseEndpoint(
        const std::string& endpoint,
        unsigned int& ip,
        unsigned int& port
    ) {
        const std::size_t separator =
            endpoint.find(':');

        if (separator == std::string::npos) {
            return false;
        }

        try {
            ip = std::stoul(
                endpoint.substr(0, separator),
                nullptr,
                16
            );

            port = std::stoul(
                endpoint.substr(separator + 1),
                nullptr,
                16
            );
        } catch (...) {
            return false;
        }

        return true;
    }

    static std::string procHexToIpv4(
        unsigned int value
    ) {
        in_addr address{};
        address.s_addr = htonl(value);

        char buffer[INET_ADDRSTRLEN]{};

        if (inet_ntop(
                AF_INET,
                &address,
                buffer,
                sizeof(buffer)
            ) == nullptr) {

            return "unknown";
        }

        return buffer;
    }

    static std::unordered_map<
        unsigned long,
        unsigned long
    > buildInodePidMap(
        const std::set<unsigned long>& wantedInodes
    ) {
        std::unordered_map<
            unsigned long,
            unsigned long
        > result;

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

                    char socketBuffer[PATH_MAX]{};

                    const ssize_t length = readlink(
                        fdEntry.path().c_str(),
                        socketBuffer,
                        sizeof(socketBuffer) - 1
                    );

                    if (length <= 0) {
                        continue;
                    }

                    socketBuffer[length] = '\0';

                    const std::string target =
                        socketBuffer;

                    if (target.rfind(
                            "socket:[",
                            0
                        ) != 0) {
                        continue;
                    }

                    const std::size_t end =
                        target.find(']');

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

public:
    void scan() {
        std::vector<RawSocket> rawSockets;
        std::set<unsigned long> wantedInodes;

        std::ifstream tcpFile("/proc/net/tcp");

        if (!tcpFile.is_open()) {
            Logger::log(
                "[NETWORK] Cannot read /proc/net/tcp",
                true
            );
            return;
        }

        std::string line;
        std::getline(tcpFile, line);

        while (std::getline(tcpFile, line)) {
            std::istringstream input(line);

            std::string slot;
            std::string localEndpoint;
            std::string remoteEndpoint;
            std::string state;

            input >> slot
                  >> localEndpoint
                  >> remoteEndpoint
                  >> state;

            // Только ESTABLISHED.
            if (state != "01") {
                continue;
            }

            // Структура /proc/net/tcp после первых четырех колонок:
            // tx_queue:rx_queue, tr, tm->when, retrnsmt,
            // uid, timeout, inode.
            std::vector<std::string> columns;
            std::string column;

            while (input >> column) {
                columns.push_back(column);
            }

            if (columns.size() < 7) {
                continue;
            }

            unsigned int remoteIpHex = 0;
            unsigned int remotePortHex = 0;

            if (!parseEndpoint(
                    remoteEndpoint,
                    remoteIpHex,
                    remotePortHex
                )) {
                continue;
            }

            unsigned long inode = 0;

            try {
                inode = std::stoul(columns[6]);
            } catch (...) {
                continue;
            }

            if (remoteIpHex == 0 ||
                remotePortHex == 0 ||
                inode == 0) {
                continue;
            }

            rawSockets.push_back({
                inode,
                procHexToIpv4(remoteIpHex),
                static_cast<int>(remotePortHex)
            });

            wantedInodes.insert(inode);
        }

        const auto inodeToPid =
            buildInodePidMap(wantedInodes);

        std::unordered_map<
            std::string,
            SocketConnection
        > currentConnections;

        for (const auto& raw : rawSockets) {
            const auto owner =
                inodeToPid.find(raw.inode);

            if (owner == inodeToPid.end()) {
                continue;
            }

            const unsigned long pid =
                owner->second;

            const ProcessMeta process =
                getProcessMeta(pid);

            if (process.name == "<unknown>" ||
                isNetworkNoise(process.name)) {
                continue;
            }

            SocketConnection connection;
            connection.pid = pid;
            connection.ppid = process.ppid;
            connection.processName = process.name;
            connection.remoteIp = raw.remoteIp;
            connection.remotePort = raw.remotePort;
            connection.domain =
                resolveDomain(raw.remoteIp);

            currentConnections[
                connection.key()
            ] = connection;
        }

        for (const auto& [key, connection] :
             currentConnections) {

            if (knownConnections_.find(key) ==
                knownConnections_.end()) {

                std::stringstream message;
                message << "[WEB_CONNECT] PID: "
                        << connection.pid
                        << " | PPID: "
                        << connection.ppid
                        << " | App: ["
                        << connection.processName
                        << "] -> "
                        << connection.remoteIp
                        << ":"
                        << connection.remotePort
                        << " (Domain: "
                        << connection.domain
                        << ")";

                Logger::log(message.str());
            }
        }

        for (const auto& [key, connection] :
             knownConnections_) {

            if (currentConnections.find(key) ==
                currentConnections.end()) {

                std::stringstream message;
                message << "[WEB_DISCONN] PID: "
                        << connection.pid
                        << " | PPID: "
                        << connection.ppid
                        << " | App: ["
                        << connection.processName
                        << "] <- "
                        << connection.remoteIp
                        << ":"
                        << connection.remotePort
                        << " (Domain: "
                        << connection.domain
                        << ")";

                Logger::log(message.str());
            }
        }

        knownConnections_ =
            std::move(currentConnections);
    }
};

// ============================================================================
// EVENT FILE SYSTEM WATCHER
// ============================================================================

class EventFileSystemWatcher {
private:
    std::string watchDirectory_;

    void linuxWatchLoop() {
        const int fd = inotify_init1(0);

        if (fd < 0) {
            Logger::log(
                "[FILE] inotify initialization failed: " +
                std::string(std::strerror(errno)),
                true
            );
            return;
        }

        const int watchDescriptor = inotify_add_watch(
            fd,
            watchDirectory_.c_str(),
            IN_CREATE |
            IN_MODIFY |
            IN_DELETE |
            IN_MOVED_FROM |
            IN_MOVED_TO |
            IN_CLOSE_WRITE
        );

        if (watchDescriptor < 0) {
            Logger::log(
                "[FILE] Cannot watch directory " +
                watchDirectory_ + ": " +
                std::strerror(errno),
                true
            );
            close(fd);
            return;
        }

        Logger::log(
            "[FILE] Monitoring directory: " +
            watchDirectory_
        );

        std::vector<char> buffer(64 * 1024);

        while (true) {
            const ssize_t length = read(
                fd,
                buffer.data(),
                buffer.size()
            );

            if (length < 0) {
                if (errno == EINTR) {
                    continue;
                }

                Logger::log(
                    "[FILE] Read error: " +
                    std::string(std::strerror(errno)),
                    true
                );
                break;
            }

            ssize_t offset = 0;

            while (offset < length) {
                const auto* event =
                    reinterpret_cast<
                        const struct inotify_event*
                    >(buffer.data() + offset);

                if (event->len > 0) {
                    const fs::path path =
                        fs::path(watchDirectory_) /
                        event->name;

                    std::string eventType;

                    if (event->mask & IN_CREATE) {
                        eventType = "FILE_CREATED";
                    } else if (event->mask & IN_MODIFY) {
                        eventType = "FILE_MODIFIED";
                    } else if (event->mask & IN_CLOSE_WRITE) {
                        eventType = "FILE_CLOSED_AFTER_WRITE";
                    } else if (event->mask & IN_DELETE) {
                        eventType = "FILE_DELETED";
                    } else if (event->mask & IN_MOVED_FROM) {
                        eventType = "FILE_MOVED_FROM";
                    } else if (event->mask & IN_MOVED_TO) {
                        eventType = "FILE_MOVED_TO";
                    }

                    if (!eventType.empty() &&
                        path.filename() !=
                            "activity_log.txt") {

                        Logger::log(
                            "[" + eventType + "] " +
                            path.string()
                        );
                    }
                }

                offset +=
                    sizeof(struct inotify_event) +
                    event->len;
            }
        }

        inotify_rm_watch(fd, watchDescriptor);
        close(fd);
    }

public:
    explicit EventFileSystemWatcher(
        std::string directory
    ) : watchDirectory_(std::move(directory)) {}

    void startAsync() {
        std::thread(
            &EventFileSystemWatcher::linuxWatchLoop,
            this
        ).detach();
    }
};

// ============================================================================
// MAIN
// ============================================================================

int main() {
    Logger::init("activity_log.txt");

    Logger::log(
        "=========================================================="
    );
    Logger::log(
        " FULL EDR AGENT ACTIVE"
    );
    Logger::log(
        " Processes + Network + Files + YARA"
    );
    Logger::log(
        "=========================================================="
    );

    // Файловый мониторинг текущей папки проекта.
    // Для мониторинга /home замените аргумент на "/home".
    EventFileSystemWatcher fileWatcher(
        fs::current_path().string()
    );

    fileWatcher.startAsync();

    ProcessWatcher processWatcher;
    NetworkWatcher networkWatcher;

    Logger::log(
        "[SYSTEM] Initial process baseline is being created"
    );

    processWatcher.scan();
    networkWatcher.scan();

    Logger::log(
        "[SYSTEM] Monitoring is active"
    );

    while (true) {
        processWatcher.scan();
        networkWatcher.scan();

        std::this_thread::sleep_for(
            std::chrono::milliseconds(100)
        );
    }

    return 0;
}
