CXX      := g++
CC       := gcc
# Keep C++ flags specific to C++ compilation
CXXFLAGS := -std=c++17 -O3 -maes -mpclmul -mssse3 -DCLHASH_PORTABLE_ONLY \
            -Icrypto
# Define separate C flags - remove C++ standard, keep optimization and includes
CFLAGS   := -O3 -maes -mpclmul -mssse3 -DCLHASH_PORTABLE_ONLY \
            -Icrypto

# C sources
SRCS_C   := crypto/haraka.c \
            crypto/haraka_portable.c

# C++ sources
SRCS_CPP := crypto/verus_hash.cpp \
            crypto/verus_clhash.cpp \
            crypto/verus_clhash_portable.cpp \
            crypto/uint256.cpp \
            crypto/utilstrencodings.cpp \
            main.cpp

# Object files
OBJS     := $(SRCS_C:.c=.o) $(SRCS_CPP:.cpp=.o)
TARGET   := verushash

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@

# compile C
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# compile C++
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
