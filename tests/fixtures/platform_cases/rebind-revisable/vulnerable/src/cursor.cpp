#include <cstdlib>

struct Cursor {
    int pos;
};

int cursor_read(int take_alt) {
    Cursor *p = (Cursor *)malloc(sizeof(Cursor));
    p->pos = 0;
    free(p);
    if (take_alt == 0) {
        Cursor *fresh = (Cursor *)malloc(sizeof(Cursor));
        fresh->pos = 2;
        p = fresh;
        (void)p;
        return fresh->pos;
    }
    return p->pos;
}
