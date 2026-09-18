int sample_window_first(int count) {
    if (count <= 0 || count > 64) {
        return -1;
    }
    int window[64];
    for (int i = 0; i < count; i++) {
        window[i] = i * 2;
    }
    return window[0];
}
