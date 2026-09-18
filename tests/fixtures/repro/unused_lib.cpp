// Harmless companion translation unit for clean-run and timeout repro
// fixtures: compiles under -fsanitize=address and never crashes.
int lima_repro_unused_library_value(void) {
    return 7;
}
