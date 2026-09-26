#include <stdlib.h>
int release_rebind_read(void) { int *data = malloc(sizeof(int)); free(data); data = malloc(sizeof(int)); data[0] = 0; int result = data[0]; free(data); return result; }
