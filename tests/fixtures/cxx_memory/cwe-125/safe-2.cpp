#include <cstdlib>
int bounded_read_allocation() { int *values = (int *)malloc(sizeof(int) * 3); values[2] = 0; int result = values[2]; free(values); return result; }
