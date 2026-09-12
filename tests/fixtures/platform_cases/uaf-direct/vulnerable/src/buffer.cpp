#include <new>

struct Packet {
    int size;
};

int packet_size(void) {
    Packet *p = new Packet;
    p->size = 16;
    delete p;
    return p->size;
}
