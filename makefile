# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wno-psabi

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
	$(CXX) $(CXXFLAGS) $^ -o $@

# Compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(HEADERS)
	@mkdir -p $(OBJ_SUBDIRS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET_DIR)

# Phony target to prevent conflicts with files named "clean"
.PHONY: clean


