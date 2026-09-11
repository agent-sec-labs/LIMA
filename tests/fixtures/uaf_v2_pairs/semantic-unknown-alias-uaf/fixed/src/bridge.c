#include <stdlib.h>

struct Bridge {
    int v;
};

void *launder(void *raw);

int bridge_read(void) {
    struct Bridge *b = malloc(sizeof *b);
    void *q = launder((void *)b);
    int v = b->v;
    free(q);
    return v;
}
