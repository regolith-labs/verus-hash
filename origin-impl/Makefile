# --- paths & tools -----------------------------------------------------------
CXX ?= g++
CC  ?= gcc
AR  ?= ar

CXXFLAGS = -O2 -std=c++17 -I.
CFLAGS   = -O2 -std=c11  -I.

CPP_SRCS = verus_hash.cpp uint256.cpp
C_SRCS   = haraka_portable.c haraka_constants.c
OBJS     = $(CPP_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

LIB = libverushash.a
BIN = vecgen

# ------------------------------------------------------------------ targets --
all: $(BIN)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(BIN): vecgen.o $(LIB)
	$(CXX) $(CXXFLAGS) $^ -o $@

vecgen.o: vecgen.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) vecgen.o $(BIN) $(LIB)
.PHONY: all clean
