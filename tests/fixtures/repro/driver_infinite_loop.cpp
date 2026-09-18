// Timeout negative: never terminates, so the sandbox must kill the run
// process group when the step budget expires.
int main() {
    volatile int guard = 0;
    for (;;) {
        guard = guard + 1;
    }
    return 0;
}
