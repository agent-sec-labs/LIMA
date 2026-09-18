#include <stdlib.h>
void bounded_write_allocation(void) { int *values = malloc(sizeof(int) * 3); values[2] = 2; free(values); }
