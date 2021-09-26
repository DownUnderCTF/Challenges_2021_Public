#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

void sig_handler() {
    puts("I don't have all day... No flag for you :(");
    exit(-1);
}

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    signal(SIGALRM, sig_handler);
    alarm(60);
    srand(time(NULL) * getpid());
}

void die() {
    puts("You failed the check! No flag for you :(");
    exit(-1);
}

unsigned char X[5] = { 0x44, 0x55, 0x43, 0x54, 0x46 };
unsigned int check1() {
    char s[6];
    unsigned char t1 = 0;
    unsigned char t2 = 1;

    printf("Give me five letters: ");
    read(0, s, 5);

    for(int i = 0; i < 5; i++) {
        t1 += X[i] ^ s[i];
        t2 *= s[i] * (i+1);
    }

    if(t1 != 0 || t2 == 0) {
        die();
    }

    return t2;
}

unsigned int check2() {
    unsigned int x, y;
    int r = rand() & 0xffff;

    printf("Solve this: x + y = %d\n", r);
    scanf("%u %u", &x, &y);

    if(x == 0 || y == 0 || x <= r || y <= r) {
        die();
    }

    if(x + y != r || ((x*y) & 0xffff) < 60) {
        die();
    }

    return (x*y) & 0xffff;
}

unsigned int check3() {
    unsigned int x1, x2, x3, x4, x5;
    int r = rand() & 0xffff;

    printf("Now solve this: x1 + x2 + x3 + x4 + x5 = %d\n", r);
    scanf("%u %u %u %u %u", &x1, &x2, &x3, &x4, &x5);

    if(x1 == 0 || x2 == 0 || x3 == 0 || x4 == 0 || x5 == 0) {
        die();
    }

    if(!(x1 < x2) || !(x2 < x3) || !(x3 < x4) || !(x4 < x5)) {
        die();
    }

    if(x1 + x2 + x3 + x4 + x5 != r || (((x3 - x2)*(x5 - x4)) & 0xffff) < 60) {
        die();
    }

    return ((x3 - x2)*(x5 - x4)) & 0xffff;
}

int main() {
    init();

    unsigned int x1, x2, x3;

    x1 = check1();
    x2 = check2();
    x3 = check3();

    puts("You've passed all the checks! Please be patient as the flag loads.");
    puts("Loading flag... (this may or may not take a while)");
    sleep(x1 * x2 * x3);

    FILE* fp = fopen("flag.txt", "r");
    char flag[255];
    fgets(flag, 255, fp);
    printf("%s", flag);

    return 0;
}
