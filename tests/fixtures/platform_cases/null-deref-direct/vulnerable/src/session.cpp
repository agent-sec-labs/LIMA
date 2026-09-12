#include <cstdlib>

struct Session {
    int id;
};

int session_id(int has_session) {
    Session *s = 0;
    if (has_session) {
        s = (Session *)malloc(sizeof(Session));
    }
    return s->id;
}
