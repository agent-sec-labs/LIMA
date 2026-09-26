struct Label {
    int len;
};

int label_len(Label *label) {
    if (label == 0) {
        return -1;
    }
    return label->len;
}
