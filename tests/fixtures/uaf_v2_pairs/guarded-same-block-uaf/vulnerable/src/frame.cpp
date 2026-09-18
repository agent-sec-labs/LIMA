#include <cstdlib>

struct Frame {
    int id;
};

int frame_id(bool reset) {
    Frame *f = new Frame();
    f->id = 5;
    if (!reset) {
        return 0;
    }
    delete f;
    return f->id;
}
