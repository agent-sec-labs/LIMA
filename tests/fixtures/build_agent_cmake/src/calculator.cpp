#include "calculator.h"

#include <cstring>

namespace lima_fixture {

int add(int a, int b) {
    return a + b;
}

int parse_int(const char *text) {
    if (text == nullptr || *text == '\0') {
        return 0;
    }
    int sign = 1;
    if (*text == '-') {
        sign = -1;
        ++text;
    }
    int value = 0;
    while (*text >= '0' && *text <= '9') {
        value = value * 10 + (*text - '0');
        ++text;
    }
    return sign * value;
}

}  // namespace lima_fixture
