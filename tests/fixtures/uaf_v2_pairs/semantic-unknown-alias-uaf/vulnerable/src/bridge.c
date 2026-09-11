#include <stdlib.h>

struct Bridge {
    int v;
};

void *launder(void *raw);

int bridge_read(void) {
    struct Bridge *b = malloc(sizeof *b);
    void *q = launder((void *)b);
    free(q);
    return b->v;
}
