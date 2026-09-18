struct Guard {
    ~Guard();
};

void raii_use() {
    Guard g;
    int* p = new int(1);
    delete p;
    *p = 2;
}
