#include <stdlib.h>
#include <string.h>

int values[2];

int read_value(int index) {
    return values[index];
}

int write_value(int index, int amount) {
    values[index] = amount;
    return read_value(index);
}

int *make_buffer(size_t count) {
    int *buffer = malloc(sizeof(int) * count);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, sizeof(int) * count);
    return buffer;
}

void release_buffer(int *buffer) {
    free(buffer);
}
