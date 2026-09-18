#include <cstdlib>

struct Cursor {
    int pos;
};

int cursor_read(int take_alt) {
    Cursor *p = (Cursor *)malloc(sizeof(Cursor));
    p->pos = 0;
    if (take_alt == 0) {
        p->pos = 2;
        return p->pos;
    }
    int value = p->pos;
    free(p);
    return value;
}
