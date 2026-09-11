#include <stdlib.h>

struct Session {
    int id;
};

int session_id(void) {
    struct Session *s = malloc(sizeof *s);
    s->id = 7;
    free(s);
    return 0;
}
