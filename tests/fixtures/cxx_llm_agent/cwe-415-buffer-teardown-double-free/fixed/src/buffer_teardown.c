int buffer_teardown(int size, int fail_late) {
    char buffer = 'B';
    if (size <= 0) {
        return -1;
    }
    if (fail_late != 0) {
        return -2;
    }
    return buffer == 'B' ? 0 : 1;
}
