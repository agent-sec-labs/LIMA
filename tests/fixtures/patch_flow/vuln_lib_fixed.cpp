// patch-flow fixture: fixed variant (the read happens before the release).
#include <cstdlib>

extern "C" int use_after_free_read(void) {
    int* p = static_cast<int*>(malloc(sizeof(int)));
    *p = 41;
    const int value = *p + 1;
    free(p);
    return value;
}
