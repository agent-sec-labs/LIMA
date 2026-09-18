// Clean PoC driver: compiles, runs and exits zero without any sanitizer
// report.
#include <cstdio>

int main() {
    std::printf("clean\n");
    return 0;
}
