PLATFORM ?= native

CXXFLAGS := -std=c++23 -Wall -Wno-psabi -MMD -MP -O2
LDFLAGS :=

ifeq ($(PLATFORM),armv6)
	CXX := armv6-rpi-linux-gnueabihf-g++
	CXXFLAGS += -march=armv6 -mfpu=vfp -mfloat-abi=hard -marm
	LDFLAGS  += -static-libstdc++ -static-libgcc -pthread -latomic
else
	CXX := g++
	CXXFLAGS +=
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static -static-libstdc++ -static-libgcc
endif

# Directories
SRC_DIR := src
OBJ_DIR := objects
TARGET_DIR := target

CXXFLAGS += -I $(SRC_DIR)

# Source files
SRC := $(wildcard $(SRC_DIR)/*.cpp) \
	   $(wildcard $(SRC_DIR)/**/*.cpp) \
	   $(wildcard $(SRC_DIR)/**/**/*.cpp) \
	   $(wildcard $(SRC_DIR)/**/**/**/*.cpp) 
HEADERS := $(wildcard $(SRC_DIR)/**/*.hpp)
OBJ := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC))

# Directories for object files
OBJ_SUBDIRS := $(sort $(dir $(OBJ)))

# Target executable
TARGET := $(TARGET_DIR)/codeymccodeface
MAIN_OBJ := $(OBJ_DIR)/main.o

$(TARGET): $(OBJ) $(MAIN_OBJ)
	@mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# Compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_SUBDIRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MAIN_OBJ): main.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(patsubst %.o,%.d,$(OBJ) $(MAIN_OBJ))

BENCH_OBJ := $(OBJ) $(OBJ_DIR)/bench/bench_crypto.o

$(OBJ_DIR)/bench/bench_crypto.o: bench/bench_crypto.cpp
	@mkdir -p $(OBJ_DIR)/bench
	$(CXX) $(CXXFLAGS) -c $< -o $@

bench: $(BENCH_OBJ)
	@mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $(BENCH_OBJ) $(LDFLAGS) -o $(TARGET_DIR)/bench_crypto


# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET_DIR)

test:
	python3 -m pytest llm-tests/ -v

test-deps:
	pip3 install -r llm-tests/requirements.txt --break-system-packages

# Phony target to prevent conflicts with files named "clean"
.PHONY: clean test test-deps bench
