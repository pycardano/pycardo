#include <stdlib.h>

typedef struct {
    int key1;
    int key2;
} vkeys;

void __wbg_vkeys_free(vkeys* ptr) {
    free(ptr);
}

int main() {
    return 0;
}

// Export the function using Emscripten-specific attributes
#ifdef __EMSCRIPTEN__
#include <emscripten.h>

EMSCRIPTEN_KEEPALIVE
void wbg_vkeys_free(vkeys* ptr) {
    __wbg_vkeys_free(ptr);
}
#endif
