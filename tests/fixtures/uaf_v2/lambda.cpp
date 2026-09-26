void lambda_use() {
    int* p = new int(1);
    auto capture = [&p]() { *p = 2; };
    capture();
    delete p;
}
