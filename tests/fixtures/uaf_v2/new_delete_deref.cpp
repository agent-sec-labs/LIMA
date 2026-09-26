void use_after_free() {
    int* p = new int(1);
    delete p;
    *p = 2;
}
