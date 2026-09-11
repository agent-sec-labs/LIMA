#include <stdlib.h>

struct Ring {
    int head;
};

int ring_head(int rotate) {
    struct Ring *ring = malloc(sizeof *ring);
    ring->head = 0;
    if (rotate) {
        free(ring);
    }
    return ring->head;
}
