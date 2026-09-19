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

        const std::string prefix = critical ? "🚨 [ALERT] " : "";
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
// PROCESS METADATA & COMMAND LINE PARSER
// ============================================================================

struct ProcessMeta {
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::string name = "<unknown>";
    std::string exePath;
    std::string cmdline;
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

    // 1. Читаем /proc/PID/stat (PID, PPID, имя)
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

    // 2. Читаем полный путь к бинарнику через readlink /proc/PID/exe
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

    // 3. Читаем полные аргументы запуска из /proc/PID/cmdline (\0 разделены)
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

// ============================================================
// NOISE FILTER (ОТСЕВ СИСТЕМНОГО МУСОРА И TELEMETRY VS CODE)
// ============================================================

bool isProcessNoise(const ProcessMeta& process, const ProcessMeta& parent) {
    if (process.ppid == 2) {
        return true;
    }

    const std::string& name = process.name;
    const std::string& parentName = parent.name;

    if (name.rfind("kworker", 0) == 0 ||
        name.rfind("ksoftirqd", 0) == 0 ||
        name.rfind("migration", 0) == 0 ||
        name.rfind("cpuhp", 0) == 0) {
        return true;
    }

    if (name == "cpuUsage.sh" || parentName == "cpuUsage.sh") {
        return true;
    }
    if ((parentName == "code" || parentName.find("code") != std::string::npos) && 
        (name == "sh" || name == "sleep" || name == "cat" || name == "grep")) {
        return true;
    }

    if (name == "bwrap" ||
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
            "NetworkManager",
            "code"
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
            "[RESPONSE] 🛑 Terminating PID: " +
            std::to_string(pid) +
            " (" + name + ") | Reason: " + reason,
            true
        );

        if (kill(static_cast<pid_t>(pid), SIGKILL) == 0) {
            Logger::log(
                "[RESPONSE] Process PID " +
                std::to_string(pid) +
                " terminated successfully"
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
// PERSISTENCE WATCHER (МОНИТОРИНГ МЕХАНИЗМОВ ЗАКРЕПЛЕНИЯ)
// ============================================================================

struct PersistenceAlert {
    std::string techniqueId; // e.g. T1053.003
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

        // 1. MITRE T1053.003: Cron Jobs & Scheduled Tasks
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

        // 2. MITRE T1543.002: Systemd Services & Timers
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

        // 3. MITRE T1546.004: Shell Startup Scripts & Profiles
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

        // 4. MITRE T1098.004: SSH Authorized Keys (Backdoor Access)
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

        // 5. MITRE T1547.001: Desktop Autostart & init.d
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

        // 6. MITRE T1574.006: Dynamic Linker Hijacking (LD.so.preload)
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
    std::string techniqueId; // e.g. T1059.004
    std::string techniqueName;
    std::string description;
    bool shouldBlock = false;
};

class MitreAnalyzer {
public:
    static std::vector<MitreFinding> analyze(const ProcessMeta& process, const ProcessMeta& parent) {
        std::vector<MitreFinding> findings;

        std::string cmd = process.cmdline;
        std::string procName = process.name;
        std::string parentName = parent.name;

        // Приведение к нижнему регистру для нечувствительности к регистру
        std::string lowerCmd = cmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);
        std::string lowerParent = parentName;
        std::transform(lowerParent.begin(), lowerParent.end(), lowerParent.begin(), ::tolower);
        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);

        // 1. MITRE T1059.004: Reverse Shell через Bash /dev/tcp или /dev/udp
        if (lowerCmd.find("/dev/tcp/") != std::string::npos || lowerCmd.find("/dev/udp/") != std::string::npos) {
            findings.push_back({
                "T1059.004",
                "Unix Shell: Reverse Shell via /dev/tcp or /dev/udp",
                "Detected network pipe redirect in command line: " + cmd,
                true // Блокировать немедленно
            });
        }

        // 2. MITRE T1059: Netcat / Ncat Reverse Shell (-e /bin/sh или -c)
        if ((lowerProc == "nc" || lowerProc == "netcat" || lowerProc == "ncat") &&
            (lowerCmd.find("-e ") != std::string::npos || lowerCmd.find("-c ") != std::string::npos || lowerCmd.find("/bin/") != std::string::npos)) {
            findings.push_back({
                "T1059",
                "Command and Scripting Interpreter: Netcat Reverse Shell",
                "Netcat spawned with shell execution flag: " + cmd,
                true
            });
        }

        // 3. MITRE T1059.006: Python Interactive Reverse Shell (pty.spawn или socket redirect)
        if (lowerProc.find("python") != std::string::npos) {
            if ((lowerCmd.find("pty.spawn") != std::string::npos || lowerCmd.find("pty") != std::string::npos) &&
                (lowerCmd.find("socket") != std::string::npos || lowerCmd.find("connect") != std::string::npos)) {
                findings.push_back({
                    "T1059.006",
                    "Python: Interactive Reverse Shell PTY Injection",
                    "Python inline script opening socket with PTY shell: " + cmd,
                    true
                });
            }
        }

        // 4. MITRE T1505.003: Web Shell Activity (веб-сервер порождает командную оболочку)
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

        // 5. MITRE T1059: Download & Execute (curl ... | bash или wget ... | sh)
        if ((lowerCmd.find("curl") != std::string::npos || lowerCmd.find("wget") != std::string::npos) &&
            (lowerCmd.find("| bash") != std::string::npos || lowerCmd.find("| sh") != std::string::npos || lowerCmd.find("|bash") != std::string::npos || lowerCmd.find("|sh") != std::string::npos)) {
            findings.push_back({
                "T1059",
                "Command and Scripting Interpreter: Download & Pipe to Shell",
                "Detected pipe from web download directly into shell interpreter: " + cmd,
                true
            });
        }

        // 6. MITRE T1082 / T1087: Reconnaissance & Shadow Access
        if (lowerCmd.find("/etc/shadow") != std::string::npos || lowerCmd.find("/etc/sudoers") != std::string::npos) {
            findings.push_back({
                "T1087",
                "Account Discovery: Sensitive File Access Attempt",
                "Access to sensitive authentication file detected in command: " + cmd,
                false // Тревога без блокировки (может быть sudo grep)
            });
        }

        // 7. MITRE T1548.001: SUID / SGID Abuse
        if (lowerProc == "chmod" && (lowerCmd.find("+s") != std::string::npos || lowerCmd.find("4755") != std::string::npos || lowerCmd.find("4777") != std::string::npos)) {
            findings.push_back({
                "T1548.001",
                "Abuse Elevation Control Mechanism: SUID Bit Modification",
                "Attempt to grant SUID execution bit detected: " + cmd,
                false
            });
        }

        // 8. MITRE T1070.004: Indicator Removal (очистка истории или логов)
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
            return false;
        }

        return !matchedRule.empty();
    }
};

// ============================================================================
// PROCESS WATCHER (С ИНСПЕКЦИЕЙ ПОВЕДЕНИЯ MITRE ATT&CK)
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

                const ProcessMeta parent =
                    getProcessMeta(process.ppid);

                // Фильтруем фоновый спам VS Code и системных потоков
                if (isProcessNoise(process, parent)) {
                    continue;
                }

                // 1. Поведенческий анализ через MITRE ATT&CK Engine
                auto findings = MitreAnalyzer::analyze(process, parent);

                bool blockedByMitre = false;
                for (const auto& finding : findings) {
                    std::stringstream alertMsg;
                    alertMsg << "\n⚠️  [MITRE ATT&CK DETECTED] " << finding.techniqueId << " - " << finding.techniqueName << "\n"
                             << "  ├─ 🎯 Target PID : " << process.pid << " [" << process.name << "]\n"
                             << "  ├─ 👨‍👦 Parent     : [" << parent.name << "] (PID: " << process.ppid << ")\n"
                             << "  ├─ 📝 Details    : " << finding.description << "\n"
                             << "  └─ 🛡️  Action     : " << (finding.shouldBlock ? "KILL_PROCESS" : "ALERT_ONLY");

                    Logger::log(alertMsg.str(), true);

                    if (finding.shouldBlock && !blockedByMitre) {
                        ActiveResponder::terminateProcess(
                            process.pid,
                            process.name,
                            "MITRE ATT&CK: " + finding.techniqueId + " (" + finding.techniqueName + ")"
                        );
                        blockedByMitre = true;
                    }
                }

                if (blockedByMitre) {
                    continue;
                }

                // Обычный информационный вывод запуска процесса
                std::stringstream message;
                message << "\n[⚙️ PROC_LAUNCH] Process: [" << process.name << "] (PID: " << process.pid << ")\n"
                        << "  ├─ 👨‍👦 Parent     : [" << parent.name << "] (PID: " << process.ppid << ")\n"
                        << "  ├─ 📁 Binary Path: " << (process.exePath.empty() ? "<unknown>" : process.exePath) << "\n"
                        << "  └─ 💻 Command    : " << (process.cmdline.empty() ? process.name : process.cmdline);

                Logger::log(message.str());

                // YARA-проверка бинарника
                std::string matchedRule;
                if (!process.exePath.empty() && yara_.scanFile(process.exePath, matchedRule)) {
                    ActiveResponder::terminateProcess(
                        process.pid,
                        process.name,
                        "YARA rule matched: " + matchedRule
                    );
                    continue;
                }

                // Проверка запуска из временных директорий
                if (!process.exePath.empty() &&
                    (process.exePath.rfind("/tmp/", 0) == 0 ||
                     process.exePath.rfind("/dev/shm/", 0) == 0)) {

                    ActiveResponder::terminateProcess(
                        process.pid,
                        process.name,
                        "Execution from temporary directory: " + process.exePath
                    );
                }
            }
        } catch (...) {}

        if (!firstScan_) {
            for (const auto& [pid, name] : knownProcesses_) {
                if (currentProcesses.find(pid) == currentProcesses.end()) {
                    if (name.rfind("kworker", 0) == 0 ||
                        name.rfind("ksoftirqd", 0) == 0 ||
                        name == "cpuUsage.sh" ||
                        name == "bwrap" ||
                        name == "glycin-image-rs" ||
                        name == "glycin-svg") {
                        continue;
                    }

                    Logger::log(
                        "[🛑 PROC_EXIT]   Process: [" + name +
                        "] | PID: " + std::to_string(pid)
                    );
                }
            }
        }

        knownProcesses_ = std::move(currentProcesses);
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
        const std::size_t separator = endpoint.find(':');
        if (separator == std::string::npos) {
            return false;
        }

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

    static std::unordered_map<
        unsigned long,
        unsigned long
    > buildInodePidMap(
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
                    const std::string target = socketBuffer;

                    if (target.rfind("socket:[", 0) != 0) {
                        continue;
                    }

                    const std::size_t end = target.find(']');
                    if (end == std::string::npos) {
                        continue;
                    }

                    unsigned long inode = 0;
                    try {
                        inode = std::stoul(target.substr(8, end - 8));
                    } catch (...) {
                        continue;
                    }

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
        if (!tcpFile.is_open()) {
            return;
        }

        std::string line;
        std::getline(tcpFile, line);

        while (std::getline(tcpFile, line)) {
            std::istringstream input(line);
            std::string slot, localEndpoint, remoteEndpoint, state;

            input >> slot >> localEndpoint >> remoteEndpoint >> state;

            if (state != "01") {
                continue;
            }

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

            if (!parseEndpoint(remoteEndpoint, remoteIpHex, remotePortHex)) {
                continue;
            }

            unsigned long inode = 0;
            try {
                inode = std::stoul(columns[6]);
            } catch (...) {
                continue;
            }

            if (remoteIpHex == 0 || remotePortHex == 0 || inode == 0) {
                continue;
            }

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
            if (owner == inodeToPid.end()) {
                continue;
            }

            const unsigned long pid = owner->second;
            const ProcessMeta process = getProcessMeta(pid);

            if (process.name == "<unknown>" || isNetworkNoise(process.name)) {
                continue;
            }

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

                Logger::log(message.str());
            }
        }

        for (const auto& [key, connection] : knownConnections_) {
            if (currentConnections.find(key) == currentConnections.end()) {
                std::stringstream message;
                message << "[🌐 WEB_DISCONN] App: [" << connection.processName
                        << "] (PID: " << connection.pid << ")"
                        << " closed connection to " << connection.remoteIp
                        << ":" << connection.remotePort;

                Logger::log(message.str());
            }
        }

        knownConnections_ = std::move(currentConnections);
    }
};

// ============================================================================
// SYSTEM-WIDE RECURSIVE FILE SYSTEM & PERSISTENCE WATCHER
// ============================================================================

class EventFileSystemWatcher {
private:
    std::string rootDirectory_;
    int inotifyFd_ = -1;
    std::unordered_map<int, std::string> watches_;
    std::mutex mutex_;

    const std::vector<std::string> excludedDirectories_ = {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/var/lib/docker",
        "/var/lib/containers",
        "/var/cache"
    };

    bool isExcluded(const fs::path& path) const {
        const std::string normalized = path.lexically_normal().string();

        for (const auto& excluded : excludedDirectories_) {
            if (normalized == excluded ||
                normalized.rfind(excluded + "/", 0) == 0) {
                return true;
            }
        }

        return false;
    }

    void addWatch(const fs::path& directory) {
        if (isExcluded(directory)) {
            return;
        }

        const int watchDescriptor = inotify_add_watch(
            inotifyFd_,
            directory.c_str(),
            IN_CREATE |
            IN_MODIFY |
            IN_DELETE |
            IN_MOVED_FROM |
            IN_MOVED_TO |
            IN_CLOSE_WRITE
        );

        if (watchDescriptor < 0) {
            return;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        watches_[watchDescriptor] = directory.string();
    }

    void addRecursiveWatches() {
        try {
            if (fs::exists(rootDirectory_) && fs::is_directory(rootDirectory_)) {
                addWatch(rootDirectory_);
            }

            for (const auto& entry : fs::recursive_directory_iterator(
                     rootDirectory_,
                     fs::directory_options::skip_permission_denied)) {

                if (entry.is_directory()) {
                    addWatch(entry.path());
                }
            }
        } catch (...) {}
    }

    void linuxWatchLoop() {
        inotifyFd_ = inotify_init1(IN_NONBLOCK);

        if (inotifyFd_ < 0) {
            Logger::log(
                "[FILE] inotify initialization failed: " +
                std::string(std::strerror(errno)),
                true
            );
            return;
        }

        Logger::log("[FILE] Indexing system directories from root: " + rootDirectory_ + " ...");
        addRecursiveWatches();

        Logger::log(
            "[FILE] System-wide recursive monitoring active on: " + rootDirectory_
        );

        std::vector<char> buffer(1024 * 1024);

        while (true) {
            const ssize_t length = read(
                inotifyFd_,
                buffer.data(),
                buffer.size()
            );

            if (length < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                if (errno == EINTR) {
                    continue;
                }

                break;
            }

            ssize_t offset = 0;

            while (offset < length) {
                const auto* event = reinterpret_cast<const struct inotify_event*>(
                    buffer.data() + offset
                );

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

                    if (!isExcluded(path) && path.filename() != "activity_log.txt") {
                        const bool isDir = (event->mask & IN_ISDIR) != 0;
                        std::string eventType;

                        if (event->mask & IN_CREATE) {
                            eventType = isDir ? "DIRECTORY_CREATED" : "FILE_CREATED";
                            if (isDir) {
                                addWatch(path);
                            }
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
                            if (isDir) {
                                addWatch(path);
                            }
                        }

                        if (!eventType.empty()) {
                            // 1. Проверка на механизмы закрепления в системе (Persistence Watcher)
                            PersistenceAlert pAlert;
                            if (PersistenceWatcher::inspectPath(path, eventType, pAlert)) {
                                std::stringstream alertMsg;
                                alertMsg << "\n📌 [PERSISTENCE DETECTED] " << pAlert.techniqueId << " - " << pAlert.techniqueName << "\n"
                                         << "  ├─ 🎯 Modified Path: " << pAlert.filePath << "\n"
                                         << "  ├─ ⚡ Event Type   : " << pAlert.eventType << "\n"
                                         << "  ├─ 📝 Details      : " << pAlert.targetDescription << "\n"
                                         << "  └─ 🛡️  Category     : CRITICAL_SYSTEM_SECURITY";

                                Logger::log(alertMsg.str(), true);
                            } else {
                                // Обычный лог изменения файла
                                std::string icon = "📄";
                                if (eventType.find("DIRECTORY") != std::string::npos) icon = "📁";
                                else if (eventType == "FILE_SAVED") icon = "💾";
                                else if (eventType.find("DELETED") != std::string::npos) icon = "🗑️";
                                else if (eventType.find("MODIFIED") != std::string::npos) icon = "✏️";

                                Logger::log("[" + icon + " " + eventType + "] " + path.string());
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
    explicit EventFileSystemWatcher(std::string directory)
        : rootDirectory_(std::move(directory)) {}

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
        "  FULL EDR AGENT ACTIVE (MITRE ATT&CK + Persistence Defense)"
    );
    Logger::log(
        "=========================================================="
    );

    EventFileSystemWatcher fileWatcher("/");
    fileWatcher.startAsync();

    ProcessWatcher processWatcher;
    NetworkWatcher networkWatcher;

    Logger::log("[SYSTEM] Creating process baseline...");
    processWatcher.scan();
    networkWatcher.scan();
    Logger::log("[SYSTEM] Baseline created. EDR monitoring is active.\n");

    while (true) {
        processWatcher.scan();
        networkWatcher.scan();

        std::this_thread::sleep_for(
            std::chrono::milliseconds(100)
        );
    }

    return 0;
}
