#include <stdlib.h>
void double_free_c(void) { int *data = malloc(sizeof(int)); free(data); free(data); }
