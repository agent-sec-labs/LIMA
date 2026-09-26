// Vulnerable fixture: null pointer dereference (CWE-476).
// read_field() dereferences its parameter without a guard and the caller
// passes NULL, so the member access faults on a null address.
#include <stddef.h>

struct S {
    int field;
};

int read_field(struct S *s) {
    return s->field;
}

int caller_with_null(void) {
    return read_field(NULL);
}
