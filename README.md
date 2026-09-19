# Full EDR Agent for Linux

Учебный прототип EDR-агента на C++17 для Kali Linux и других Linux-систем. Проект отслеживает запуск процессов, сетевые TCP-соединения и изменения файловой системы, проверяет исполняемые файлы через YARA и содержит модуль активного реагирования.

> Проект находится в разработке. Это прототип для локального тестирования, а не готовая промышленная система защиты.

---

## Возможности

### Мониторинг процессов

Агент отслеживает:

- запуск новых процессов;
- завершение процессов;
- PID и PPID;
- имя процесса;
- путь к исполняемому файлу;
- родительский процесс.

При первом сканировании создаётся базовое состояние уже работающих процессов. Существующие процессы не считаются новыми.

### YARA-сканирование

При обнаружении нового процесса агент может проверить его исполняемый файл через библиотеку YARA.

В текущем прототипе используются тестовые сигнатуры:

- `EICAR-STANDARD-ANTIVIRUS-TEST-FILE`;
- `CUSTOM_MALWARE_SIGNATURE_TEST`.

Правила встроены в исходный код и предназначены только для проверки работы механизма.

### Active Responder

При совпадении YARA-правила или запуске бинарника из временной директории агент может завершить процесс через `SIGKILL`.

Проверяются пути:

- `/tmp/`;
- `/dev/shm/`.

Для защиты системы предусмотрен список критических процессов, которые агент не должен завершать.

### Мониторинг TCP-соединений

Агент анализирует `/proc/net/tcp` и сопоставляет сетевые сокеты с процессами через `/proc/<pid>/fd`.

В логах отображаются:

- PID;
- PPID;
- имя процесса;
- удалённый IP;
- удалённый порт;
- результат reverse DNS.

Пример:

```text
[WEB_CONNECT] PID: 47466 | PPID: 1511 | App: [firefox-esr] -> 142.250.185.14:443 (Domain: google.com)
```

### DNS-мониторинг

Отдельный файл `dns_watcher.cpp` использует `libpcap` для перехвата DNS-запросов UDP/53 и пытается связать исходный UDP-порт с PID процесса.

Пример:

```text
[DNS_QUERY] PID: 47466 | PPID: 1511 | App: [firefox-esr] -> youtube.com
```

DNS-монитор нужен для определения доменных имён, потому что `/proc/net/tcp` содержит IP-адреса, но не исходные домены.

### Мониторинг файлов

Основной агент использует `inotify` и отслеживает изменения в текущей директории запуска:

- создание файла;
- изменение файла;
- удаление файла;
- закрытие файла после записи;
- перемещение файла.

По умолчанию мониторится текущая папка проекта. Чтобы отслеживать `/home`, измените в `main()`:

```cpp
EventFileSystemWatcher fileWatcher(
    fs::current_path().string()
);
```

на:

```cpp
EventFileSystemWatcher fileWatcher("/home");
```

---

## Структура проекта

```text
Endpoint-Detection-Mini-EDR/
├── app.cpp                  # Основной EDR-агент
├── dns_watcher_cpp17.cpp    # Отдельный DNS-монитор
├── app                      # Исполняемый файл основного агента
├── dns_watcher              # Исполняемый файл DNS-монитора
├── activity_log.txt         # Текстовый лог основного агента
└── .vscode/
    └── tasks.json           # Задачи сборки VS Code
```

Не добавляйте бинарные файлы `app` и `dns_watcher` в Git. Лучше добавить их в `.gitignore`:

```gitignore
app
dns_watcher
activity_log.txt
```

---

## Требования

- Kali Linux или другой Linux-дистрибутив;
- GCC/G++ с поддержкой C++17;
- `libyara-dev` для основного агента;
- `libpcap-dev` для DNS-монитора;
- права root для доступа к `/proc/<pid>/fd`, сетевым данным и захвату пакетов.

Установка зависимостей:

```bash
sudo apt update
sudo apt install g++ libyara-dev libpcap-dev -y
```

---

## Сборка основного EDR-агента

Перейдите в каталог проекта:

```bash
cd ~/Desktop/Endpoint-Detection-Mini-EDR/Endpoint-Detection-Mini-EDR
```

Соберите `app.cpp`:

```bash
g++ -std=c++17 -O2 -Wall -Wextra \
    app.cpp \
    -o app \
    -lyara \
    -pthread
```

Запустите:

```bash
sudo ./app
```

Основной агент использует библиотеку YARA, поэтому ему нужен флаг:

```text
-lyara
```

---

## Сборка DNS-монитора

DNS-монитор собирается отдельно:

```bash
g++ -std=c++17 -O2 -Wall -Wextra \
    dns_watcher_cpp17.cpp \
    -o dns_watcher \
    -lpcap \
    -pthread
```

Для DNS-монитора нужен флаг:

```text
-lpcap
```

Запуск:

```bash
sudo ./dns_watcher
```

Не используйте `-lyara` при сборке `dns_watcher_cpp17.cpp`: DNS-монитор не использует YARA.

---

## Настройка сборки в VS Code

Создайте файл `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build EDR agent",
            "type": "shell",
            "command": "/usr/bin/g++",
            "args": [
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "${workspaceFolder}/app.cpp",
                "-o",
                "${workspaceFolder}/app",
                "-lyara",
                "-pthread"
            ],
            "options": {
                "cwd": "${workspaceFolder}"
            },
            "problemMatcher": [
                "$gcc"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        },
        {
            "label": "Build DNS watcher",
            "type": "shell",
            "command": "/usr/bin/g++",
            "args": [
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "${workspaceFolder}/dns_watcher_cpp17.cpp",
                "-o",
                "${workspaceFolder}/dns_watcher",
                "-lpcap",
                "-pthread"
            ],
            "options": {
                "cwd": "${workspaceFolder}"
            },
            "problemMatcher": [
                "$gcc"
            ]
        }
    ]
}
```

Запуск задачи:

```text
Ctrl + Shift + P
→ Tasks: Run Task
→ Build EDR agent
```

или:

```text
Ctrl + Shift + P
→ Tasks: Run Task
→ Build DNS watcher
```

---

## Проверка работы основного агента 

### Процесс

Откройте второй терминал и запустите:

```bash
sleep 20
```

В логе должно появиться событие запуска и завершения процесса:

```text
[PROC_LAUNCH] PID: 12345 | PPID: 4185 | Parent: [bash] | App: [sleep]
[PROC_EXIT] PID: 12345 | App: [sleep]
```

### Файлы

```bash
touch test_file.txt
echo "test" >> test_file.txt
rm test_file.txt
```

Пример:

```text
[FILE_CREATED] /path/to/project/test_file.txt
[FILE_MODIFIED] /path/to/project/test_file.txt
[FILE_DELETED] /path/to/project/test_file.txt
```

### Сеть

```bash
curl https://example.com
```

Пример:

```text
[WEB_CONNECT] PID: 12346 | PPID: 4185 | App: [curl] -> 93.184.216.34:443 (Domain: example.com)
```

---

## Проверка DNS-монитора

Запустите DNS-монитор:

```bash
sudo ./dns_watcher
```

В другом терминале выполните:

```bash
curl https://youtube.com
curl https://github.com
```

Ожидаемый вывод:

```text
[DNS_QUERY] PID: 47466 | PPID: 1511 | App: [curl] -> youtube.com
[DNS_QUERY] PID: 47466 | PPID: 1511 | App: [curl] -> github.com
```

---

## Почему DNS-запрос может не отображаться

DNS-монитор видит обычные DNS-запросы через UDP/53. Он может не увидеть домен, если:

- браузер использует DNS-over-HTTPS;
- браузер использует DNS-over-TLS;
- DNS-запрос был взят из кэша;
- используется локальный DNS-прокси;
- запрос выполняется через VPN;
- приложение использует заранее известный IP-адрес.

Кроме того, DNS-монитор показывает домен, но не полный URL страницы. Например:

```text
youtube.com
```

но не:

```text
youtube.com/watch?v=...
```

---

## Ограничения текущего прототипа

- Процессы проверяются через периодический просмотр `/proc`, поэтому очень короткие процессы могут быть пропущены.
- Сетевые соединения собираются из `/proc/net/tcp` и могут исчезнуть до момента сканирования.
- Reverse DNS не всегда соответствует фактическому домену сервиса.
- DNS-over-HTTPS и DNS-over-TLS не анализируются.
- `inotify` следит только за указанной директорией и её событиями.
- RWX-анализ памяти пока не добавлен.
- Аудит `/proc/[pid]/cmdline` и детектор Reverse Shell пока не добавлены.
- Автоматическое завершение процесса требует осторожной настройки правил, иначе возможны ложные срабатывания.

---

## План дальнейшего развития

1. Перевести текстовые логи в JSON Lines.
2. Добавить единый фильтр шума для процессов, сети и файлов.
3. Перейти от polling процессов к auditd или eBPF.
4. Добавить аудит командной строки.
5. Реализовать безопасный детектор Reverse Shell.
6. Добавить RWX Hunt с режимом только обнаружения.
7. Вынести YARA-правила в отдельную папку.
8. Добавить конфигурационный файл правил.
9. Добавить центральный сервер сбора событий.
10. Создать веб-панель для анализа событий.

---

## Лицензия

Проект предназначен для локального тестирования и разработки защитных инструментов в контролируемой среде.
