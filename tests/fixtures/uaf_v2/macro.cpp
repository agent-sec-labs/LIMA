#define RELEASE(p) delete p

void macro_use() {
    int* p = new int(1);
    RELEASE(p);
    *p = 2;
}
