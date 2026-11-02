#include "calculator.h"

#include <cstdio>

int main() {
    std::printf("%d %d\n",
        lima_fixture::add(2, 3),
        lima_fixture::parse_int("-17"));
    return 0;
}
