void guarded_use(bool flag) {
    int* p = new int(1);
    if (flag) {
        delete p;
        *p = 2;
    }
}
