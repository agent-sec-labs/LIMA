// PoC driver: triggers the heap-use-after-free in vuln_lib.cpp.
#include <cstdio>

extern "C" int use_after_free_read(void);

int main() {
    const int value = use_after_free_read();
    std::printf("%d\n", value);
    return 0;
}
