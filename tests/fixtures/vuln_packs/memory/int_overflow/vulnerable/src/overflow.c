// Vulnerable fixture: integer overflow to memory corruption (CWE-190).
// The allocation size is computed as count * sizeof(int) and truncated to
// int: for large counts the product wraps, malloc receives the wrapped
// small size, and the memset then writes the full logical number of bytes.
#include <stdlib.h>
#include <string.h>

int *make_table(int count) {
    int total = (int)(count * sizeof(int));  /* wraps for large counts */
    int *table = (int *)malloc(total);
    if (table == NULL) {
        return NULL;
    }
    memset(table, 0, (size_t)count * sizeof(int));  /* full logical size */
    return table;
}
