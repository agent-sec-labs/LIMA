#include <cstdlib>
void release_without_reuse() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); data = nullptr; }
