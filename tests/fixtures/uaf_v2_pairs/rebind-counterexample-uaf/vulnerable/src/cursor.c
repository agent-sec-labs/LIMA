#include <stdlib.h>

struct Node {
    int v;
};

int cursor_read(struct Node *fresh) {
    struct Node *p = malloc(sizeof *p);
    p->v = 1;
    free(p);
    p = fresh;
    return p->v;
}
