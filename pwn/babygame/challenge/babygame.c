#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char   NAME[32];
char*  RANDBUF;

void init();
void print_username();
void set_username();
int get_num();
void print_menu();
void game();


int main() {
	init();
    printf("Welcome, what is your name?\n");
    read(0, NAME, 32);
    RANDBUF = "/dev/urandom";

    while (1) {
        print_menu();
        int c = get_num();
        switch (c) {
            case 1:
                set_username();
                break;
            case 2:
                print_username();
                break;
            case 1337:
                game();
                break;
            default:
                printf("Invalid choice.\n");
        }
    }
}


void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}


int get_num() {
    char num[12];
    read(0, num, 11);
    return atoi(num);
}


void print_menu() {
    printf("1. Set Username\n");
    printf("2. Print Username\n");
    printf("> ");
}


void set_username() {
    printf("What would you like to change your username to?\n");
    fread(NAME, 1, strlen(NAME), stdin);
}


void print_username() {
    puts(NAME);
}


void game() {
    FILE* fd = fopen(RANDBUF, "rb");
    char buf[4];
    fread(buf, 1, 4, fd);

    printf("guess: ");
    int guess = get_num();

    if (guess == *(int*)buf) {
        system("/bin/sh");
    }
}
