#include <cstdlib>
void release_rebind_write() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); data = static_cast<int *>(std::malloc(sizeof(int))); data[0] = 1; std::free(data); }
