void try_use() {
    int* p = new int(1);
    try {
        *p = 1;
    } catch (...) {
    }
    delete p;
}
