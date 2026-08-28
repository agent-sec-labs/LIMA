int bounded_read_local(const int *values, int index) { int result = index >= 0 && index < 9 ? values[index] : 0; return result; }
