int bounded_read_pointer(const int *values, int index) { return index >= 0 && index < 8 ? values[index] : 0; }
