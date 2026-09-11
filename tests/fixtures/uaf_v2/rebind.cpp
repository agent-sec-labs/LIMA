void rebind_use() {
    int* p = new int(1);
    delete p;
    p = new int(3);
    *p = 4;
}
