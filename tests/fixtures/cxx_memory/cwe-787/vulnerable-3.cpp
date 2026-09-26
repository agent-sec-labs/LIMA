#include <array>
void oob_write_container() { std::array<int, 2> values{}; values[2] = 3; }
