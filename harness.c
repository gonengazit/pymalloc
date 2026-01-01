#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

// Use a fixed-size array for pointers to avoid heap usage
void* ptrs[256];
uintptr_t base = 0;

// Minimalistic integer-to-string for system calls
void write_long(long n) {
    char buf[32];
    int i = 0;
    if (n == 0) buf[i++] = '0';
    else {
        int is_neg = 0;
        if (n < 0) { is_neg = 1; n = -n; }
        while (n > 0) {
            buf[i++] = (n % 10) + '0';
            n /= 10;
        }
        if (is_neg) buf[i++] = '-';
    }
    // Reverse buffer
    for (int j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - j - 1];
        buf[i - j - 1] = tmp;
    }
    buf[i++] = '\n';
    write(STDOUT_FILENO, buf, i);
}

// Minimalistic string-to-int parser
int parse_int(char **cursor) {
    int res = 0;
    while (**cursor == ' ' || **cursor == '\n' || **cursor == '\r') (*cursor)++;
    while (**cursor >= '0' && **cursor <= '9') {
        res = res * 10 + (**cursor - '0');
        (*cursor)++;
    }
    return res;
}

int main() {
    char input_buf[4096];
    ssize_t n = read(STDIN_FILENO, input_buf, sizeof(input_buf) - 1);
    if (n <= 0) return 0;
    input_buf[n] = '\0';

    char *cursor = input_buf;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\n' || *cursor == '\r') cursor++;
        if (*cursor == '\0') break;

        char op = *cursor++;
        if (op == 'M') {
            int size = parse_int(&cursor);
            int idx = parse_int(&cursor);
            void* p = malloc(size);

            if (base == 0) base = (uintptr_t)p;

            if (!p) write(STDOUT_FILENO, "NULL\n", 5);
            else write_long((uintptr_t)p - base);

            ptrs[idx] = p;
        } else if (op == 'F') {
            int idx = parse_int(&cursor);
            free(ptrs[idx]);
            // Output "FREE" so the Python side stays in sync
            write(STDOUT_FILENO, "FREE\n", 5);
        }
    }
    return 0;
}
