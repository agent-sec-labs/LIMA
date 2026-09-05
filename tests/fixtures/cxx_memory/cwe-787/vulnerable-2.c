#include <stdlib.h>
void oob_write_allocation(void) { int *values = malloc(sizeof(int) * 2); values[2] = 2; free(values); }
