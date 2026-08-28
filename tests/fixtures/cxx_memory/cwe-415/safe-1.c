#include <stdlib.h>
void free_once_c(void) { int *data = malloc(sizeof(int)); free(data); data = NULL; }
