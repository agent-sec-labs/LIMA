// patch-flow fixture: heap-use-after-free (vulnerable variant).
#include <cstdlib>

extern "C" int use_after_free_read(void) {
    int* p = static_cast<int*>(malloc(sizeof(int)));
    *p = 41;
    free(p);
    return *p + 1;
}
