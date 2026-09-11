template <typename T>
void template_use(T value) {
    int* p = new int(1);
    *p = 2;
}

void instantiate() {
    template_use<int>(1);
}
