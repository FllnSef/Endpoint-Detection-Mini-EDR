CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread

all: app dns_watcher

app: app.cpp
	$(CXX) $(CXXFLAGS) app.cpp -o app -lyara

dns_watcher: dns_watcher.cpp
	$(CXX) $(CXXFLAGS) dns_watcher.cpp -o dns_watcher -lpcap

clean:
	rm -f app dns_watcher activity_log.txt
