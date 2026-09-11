void alias_chain_use() {
    int* p = new int(1);
    int* q = p;
    int* r = q;
    delete p;
    *r = 2;
}
