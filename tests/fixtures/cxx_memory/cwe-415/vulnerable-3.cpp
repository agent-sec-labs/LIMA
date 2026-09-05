#include <cstdlib>
void double_free_std() { int *data = static_cast<int *>(std::malloc(sizeof(int))); std::free(data); std::free(data); }
