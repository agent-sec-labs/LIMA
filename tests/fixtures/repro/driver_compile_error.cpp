// Compile-failure negative: references an undeclared symbol so clang++-14
// must reject the translation unit before any execution.
int main() {
    this_function_does_not_exist();
    return 0;
}
