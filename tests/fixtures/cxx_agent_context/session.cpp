#include <cstdlib>

class Session {
public:
    void open(int capacity);
    void close();
    int read(int slot);
private:
    int *slots_;
    size_t capacity_;
};

void Session::open(int capacity) {
    slots_ = new int[capacity];
    capacity_ = static_cast<size_t>(capacity);
}

void Session::close() {
    delete[] slots_;
    slots_ = nullptr;
}

int Session::read(int slot) {
    return slots_[slot];
}

Session *create_session(int capacity) {
    Session *session = new Session();
    session->open(capacity);
    return session;
}

void destroy_session(Session *session) {
    session->close();
    delete session;
}
