#include <stdlib.h>
int use_after_free_read(void) { int *data = malloc(sizeof(int)); free(data); return data[0]; }
