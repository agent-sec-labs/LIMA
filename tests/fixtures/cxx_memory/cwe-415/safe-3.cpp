#include <cstdlib>
void free_once_std() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); data = nullptr; }
