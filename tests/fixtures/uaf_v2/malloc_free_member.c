#include <stdlib.h>

struct item {
    int value;
};

void use_after_free(void) {
    struct item* p = (struct item*)malloc(sizeof(struct item));
    p->value = 1;
    free(p);
    p->value = 2;
}
