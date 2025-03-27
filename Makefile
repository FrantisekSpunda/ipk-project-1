CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -I./src
LDFLAGS = -lpcap

SRC_DIR = src
TARGET = ipk-l4-scan

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)

all: $(TARGET)

$(TARGET):
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: all
	sudo ./$(TARGET) $(ARGS)
