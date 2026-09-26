// Fixed fixture: null pointer dereference (CWE-476).
// The same member access, guarded: a null argument returns the error value
// instead of faulting.
#include <stddef.h>

struct S {
    int field;
};

int read_field(struct S *s) {
    if (s == NULL) {
        return -1;
    }
    return s->field;
}

int caller_with_null(void) {
    return read_field(NULL);
}
