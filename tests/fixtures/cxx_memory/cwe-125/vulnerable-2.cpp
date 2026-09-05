#include <cstdlib>
int oob_read_allocation() { int *values = (int *)malloc(sizeof(int) * 2); return values[2]; }
