#include <stdlib.h>

int scratch_store_write(int count, int seed) {
    int *scratch = malloc((size_t) count * sizeof(int));
    if (scratch == 0) {
        return -1;
    }
    for (int i = 0; i <= count; i++) {
        scratch[i] = seed + i;
    }
    free(scratch);
    return 0;
}
