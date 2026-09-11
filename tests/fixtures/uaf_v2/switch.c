#include <stdlib.h>

void switch_use(int n) {
    char* p = (char*)malloc(4);
    switch (n) {
    case 1:
        *p = 'a';
        break;
    default:
        break;
    }
}
