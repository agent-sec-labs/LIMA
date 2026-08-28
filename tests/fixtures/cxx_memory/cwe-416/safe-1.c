#include <stdlib.h>
int release_then_null(void) { int *data = malloc(sizeof(int)); free(data); data = NULL; return 0; }
