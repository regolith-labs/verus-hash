#include <cstring>
extern "C" void memory_cleanse(void* p, size_t n) { std::memset(p, 0, n); }
