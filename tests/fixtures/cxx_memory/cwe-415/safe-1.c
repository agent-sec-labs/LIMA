#include <stdlib.h>
void free_rebind_free_c(void) { int *data = malloc(sizeof(int)); free(data); data = malloc(sizeof(int)); free(data); }
