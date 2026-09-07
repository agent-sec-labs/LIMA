int scratch_store_write(int count, int seed) {
    if (count <= 0 || count > 64) {
        return -1;
    }
    int scratch[64];
    for (int i = 0; i < count; i++) {
        scratch[i] = seed + i;
    }
    return scratch[count - 1] == seed ? 0 : 1;
}
