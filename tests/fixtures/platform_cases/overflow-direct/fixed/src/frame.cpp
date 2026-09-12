#include <new>

int frame_write(int count) {
    if (count > 4 || count < 0) {
        return -1;
    }
    char *buf = new char[4];
    for (int i = 0; i < count; ++i) {
        buf[i] = (char)i;
    }
    delete[] buf;
    return 0;
}
