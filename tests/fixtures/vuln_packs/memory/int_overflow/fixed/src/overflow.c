// Fixed fixture: integer overflow to memory corruption (CWE-190).
// The size arithmetic runs in size_t behind an explicit range check, so
// the allocation and the initialization length can no longer disagree.
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int *make_table(int count) {
    size_t total;
    int *table;
    if (count <= 0 || (size_t)count > SIZE_MAX / sizeof(int)) {
        return NULL;
    }
    total = (size_t)count * sizeof(int);
    table = (int *)malloc(total);
    if (table == NULL) {
        return NULL;
    }
    memset(table, 0, total);
    return table;
}
