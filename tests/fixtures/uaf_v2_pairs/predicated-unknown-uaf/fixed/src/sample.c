#include <stdlib.h>

struct Sample {
    int v;
};

int sample_pick(int x) {
    struct Sample *s = malloc(sizeof *s);
    s->v = x;
    int picked = s->v;
    if (x > 10) {
        free(s);
    }
    return picked;
}
