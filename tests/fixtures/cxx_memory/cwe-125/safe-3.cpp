#include <array>
int bounded_read_container() { std::array<int, 3> values{}; int result = values[2]; return result; }
