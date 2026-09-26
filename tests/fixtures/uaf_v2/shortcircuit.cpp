void shortcircuit_use(int* q) {
    int* p = new int(1);
    if (p && (q = p) != 0) {
        *q = 1;
    }
    delete p;
}
