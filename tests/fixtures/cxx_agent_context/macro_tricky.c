#define BEGIN_NS namespace tricky {
#define END_NS }

#define MYSTERY_BODY return \

void broken_function(void) {
    MYSTERY_BODY
        0;
}
