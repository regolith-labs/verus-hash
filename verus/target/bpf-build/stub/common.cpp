#include <cstring>
// Provide a basic implementation if the original is missing
extern "C" void memory_cleanse(void* p, size_t n) { std::memset(p, 0, n); }
