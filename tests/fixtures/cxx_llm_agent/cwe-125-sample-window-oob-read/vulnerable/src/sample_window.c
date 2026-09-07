#include <stdlib.h>

int sample_window_first(int count) {
    int *window = malloc((size_t) count * sizeof(int));
    if (window == 0) {
        return -1;
    }
    for (int i = 0; i < count; i++) {
        window[i] = i * 2;
    }
    int first_outside = window[count];
    free(window);
    return first_outside;
}
