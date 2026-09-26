struct Label {
    int len;
};

int label_len(Label *label) {
    if (label == nullptr) {
        return -1;
    }
    return label->len;
}
