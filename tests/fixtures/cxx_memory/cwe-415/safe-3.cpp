#include <cstdlib>
void free_rebind_free_std() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); }
