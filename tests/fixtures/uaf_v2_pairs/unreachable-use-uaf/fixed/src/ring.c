#include <stdlib.h>

struct Ring {
    int head;
};

int ring_head(int rotate) {
    struct Ring *ring = malloc(sizeof *ring);
    ring->head = 0;
    int head = ring->head;
    if (rotate) {
        free(ring);
    }
    return head;
}
