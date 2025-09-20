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
	LDFLAGS += -static -static-libstdc++ -static-libgcc -luring
endif

# Directories
SRC_DIR := src
OBJ_DIR := objects
TARGET_DIR := target

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

# Compile and link
$(TARGET): $(OBJ)
	@mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@
#	strip $(TARGET)

# Compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_SUBDIRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(patsubst %.o,%.d,$(OBJ))

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET_DIR)

# Phony target to prevent conflicts with files named "clean"
.PHONY: clean


