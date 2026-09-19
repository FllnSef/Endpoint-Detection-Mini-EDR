CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread

all: app

app: app.cpp
	$(CXX) $(CXXFLAGS) app.cpp -o app -lyara -lpcap

clean:
	rm -f app activity_log.txt rules.conf
