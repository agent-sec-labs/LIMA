#include <cstdlib>
void use_after_free_write() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); data[0] = 1; }
