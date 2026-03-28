PLATFORM ?= native

CXXFLAGS_NO_OPT := -std=c++23 -Wall -Wno-psabi -MMD -MP \
	-ffunction-sections -fdata-sections -fvisibility=hidden -flto

LDFLAGS :=

ifeq ($(PLATFORM),armv6)
	CXX := armv6-rpi-linux-gnueabihf-g++
	CXXFLAGS_NO_OPT += -march=armv6 -mfpu=vfp -mfloat-abi=hard -marm
	LDFLAGS  += -static-libstdc++ -static-libgcc -pthread -latomic -Wl,--gc-sections
else
	CXX := g++
	LDFLAGS += -Wl,-dead_strip -Wl,-S
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static -static-libstdc++ -static-libgcc
endif

# Directories
SRC_DIR := src
OBJ_DIR := objects
TARGET_DIR := target

CXXFLAGS_NO_OPT += -I $(SRC_DIR)

CXXFLAGS := $(CXXFLAGS_NO_OPT)  -O2
CXXFLAGS_CRYPTO := $(CXXFLAGS_NO_OPT) -O3
CXXFLAGS_SIZE   := $(CXXFLAGS_NO_OPT) -Oz

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
	$(CXX) $(CXXFLAGS_CRYPTO) $^ $(LDFLAGS) -o $@

# Cryptography files: -O3 (tight arithmetic loops benefit from full optimisation)
$(OBJ_DIR)/TLS/Cryptography/%.o: $(SRC_DIR)/TLS/Cryptography/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_CRYPTO) -c $< -o $@

# TLS non-crypto code: -Os (no tight arithmetic, code size matters more than speed)
$(OBJ_DIR)/TLS/%.o: $(SRC_DIR)/TLS/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_SIZE) -c $< -o $@

# HTTP protocol handlers and application code: -Os (favour smaller code)
$(OBJ_DIR)/HTTP/%.o: $(SRC_DIR)/HTTP/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_SIZE) -c $< -o $@

$(OBJ_DIR)/Application/%.o: $(SRC_DIR)/Application/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_SIZE) -c $< -o $@

# Default: compile all other source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_SUBDIRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MAIN_OBJ): main.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(patsubst %.o,%.d,$(OBJ) $(MAIN_OBJ))

BENCH_OBJ := $(OBJ) $(OBJ_DIR)/bench/bench_chacha.o

$(OBJ_DIR)/bench/bench_chacha.o: bench/bench_chacha.cpp
	@mkdir -p $(OBJ_DIR)/bench
	$(CXX) $(CXXFLAGS_CRYPTO) -c $< -o $@

bench: $(BENCH_OBJ)
	@mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS_CRYPTO) $(BENCH_OBJ) $(LDFLAGS) -o $(TARGET_DIR)/bench_chacha


# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET_DIR)

test:
	python3 -m pytest llm-tests/ -v

test-deps:
	pip3 install -r llm-tests/requirements.txt --break-system-packages

armv6: | $(TARGET_DIR)
	docker build --progress=plain -t containerymccontainerface -f Dockerfile.armv6 .
	c_id=$$(docker create containerymccontainerface) && \
	  docker cp $$c_id:/target/codeymccodeface $(TARGET_DIR)/codeymccodeface.armv6 ; \
	  docker rm $$c_id

# Phony target to prevent conflicts with files named "clean"
.PHONY: clean test test-deps bench armv6
