int session_release(int size) {
    char session = 'S';
    if (size <= 0) {
        return -1;
    }
    return session == 'S' ? size : 0;
}
