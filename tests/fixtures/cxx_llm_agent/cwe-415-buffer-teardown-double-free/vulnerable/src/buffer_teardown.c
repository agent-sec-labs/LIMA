#include <stdlib.h>

int buffer_teardown(int size, int fail_late) {
    char *buffer = malloc((size_t) size);
    if (buffer == 0) {
        return -1;
    }
    buffer[0] = 'B';
    free(buffer);
    if (fail_late != 0) {
        free(buffer);
        return -2;
    }
    return 0;
}
