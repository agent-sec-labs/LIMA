void loop_use(int n) {
    int* p = new int(1);
    delete p;
    for (int i = 0; i < n; ++i) {
        *p = i;
    }
}
