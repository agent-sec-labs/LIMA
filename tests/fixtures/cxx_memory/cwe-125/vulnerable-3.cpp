#include <array>
int oob_read_container() { std::array<int, 2> values{}; int result = values[2]; return result; }
