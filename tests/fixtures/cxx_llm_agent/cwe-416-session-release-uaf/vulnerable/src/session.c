#include <stdlib.h>

int session_release(int size) {
    char *session = malloc((size_t) size);
    if (session == 0) {
        return -1;
    }
    session[0] = 'S';
    free(session);
    return session[0] == 'S' ? 1 : 0;
}
