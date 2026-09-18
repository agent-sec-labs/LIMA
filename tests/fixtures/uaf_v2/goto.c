#include <stdlib.h>

void goto_use(int n) {
    char* p = (char*)malloc(4);
    if (n > 0) {
        goto cleanup;
    }
    *p = 'x';
cleanup:
    free(p);
}
