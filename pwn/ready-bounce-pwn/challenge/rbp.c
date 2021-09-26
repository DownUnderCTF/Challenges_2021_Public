#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

long read_long() {
    char buf[20];
    read(0, buf, 19);
    return atol(buf);
}

int main() {
    init();

    char name[0x18];
    printf("Hi there! What is your name? ");
    read(0, name, 0x18);

    puts("That is an interesting name.");
    printf("Do you have a favourite number? ");

    asm("add %0, %%rbp;" : : "r"(read_long()));

    return 0;
}
