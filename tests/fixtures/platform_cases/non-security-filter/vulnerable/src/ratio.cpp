int ratio_percent(int part, int whole) {
    if (whole == 0) {
        return 0;
    }
    return part * whole / 100;
}
