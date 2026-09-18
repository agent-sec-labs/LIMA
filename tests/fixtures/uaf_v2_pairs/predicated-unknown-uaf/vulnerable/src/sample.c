#include <stdlib.h>

struct Sample {
    int v;
};

int sample_pick(int x) {
    struct Sample *s = malloc(sizeof *s);
    s->v = x;
    if (x > 10) {
        free(s);
    }
    if (x <= 10) {
        return s->v;
    }
    return 0;
}
