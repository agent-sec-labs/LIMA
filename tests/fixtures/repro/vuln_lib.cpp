// UAF fixture: container tests pin faulting/freed/allocated lines at 8/7/5.
#include <cstdlib>

extern "C" int use_after_free_read(void) {
    int* p = static_cast<int*>(malloc(sizeof(int)));
    *p = 41;
    free(p);
    return *p + 1;
}
