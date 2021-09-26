#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 8
#define MAX_NUM_BLOCKS 11
#define NOTE_SIZE 88

unsigned long X, A, B;

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	int fd = open("/dev/random", 'r');
	read(fd, &X, 8);
	read(fd, &A, 8);
	read(fd, &B, 8);
	A |= 5;
	B |= 1;
}

int read_int() {
	char buf[10];
	read(0, buf, 9);
	return atoi(buf);
}

int menu() {
	puts("1. Write note");
	puts("2. Read note");
	puts("3. Append to note");
	puts("0. Quit");
	printf("> ");
	int choice = read_int();
	return choice;
}

long lcg_next() {
	X = A * X + B;
	return X;
}

void encrypt(char* pt) {
	int num_blocks = strlen(pt) / BLOCK_SIZE;
	if(strlen(pt) % BLOCK_SIZE > 0) {
		num_blocks++;
	}
	if(num_blocks > MAX_NUM_BLOCKS) {
		num_blocks = MAX_NUM_BLOCKS;
	}
	unsigned long* ct = (unsigned long*)pt;
	for(int i = 0; i < num_blocks; i++) {
		*(unsigned long*)(ct + i) = *(ct + i) ^ lcg_next();
	}
}

void write_note(char* note) {
	memset(note, 0, NOTE_SIZE);
	printf("Enter note contents: ");
	read(0, note, NOTE_SIZE);
	encrypt(note);
}

void read_note(char* note) {
	for(int i = 0; i < strlen(note); i++) {
		printf("%02x", *(unsigned char*)(note + i));
	}
	printf("\n");
}

void append_to_note(char* note) {
	if(*(note + NOTE_SIZE - 1) > '\0') {
		puts("Note is full!");
		return;
	}
	char* app = (char*) malloc(BLOCK_SIZE);
	printf("Enter note contents to append: ");
	read(0, app, BLOCK_SIZE);
	char* dest = strchr(note, '\0');
	strncpy(dest, app, BLOCK_SIZE);
	dest[BLOCK_SIZE - 1] = '\0';
	encrypt(dest);
}

void win() {
	system("/bin/sh");
}

void vuln() {
	char note[NOTE_SIZE];
	int choice;

	while(1) {
		choice = menu();
		switch(choice) {
			case 0:
				return;
			case 1:
				write_note(note);
				break;
			case 2:
				read_note(note);
				break;
			case 3:
				append_to_note(note);
				break;
			default:
				puts("Invalid choice");
		}
	}
}

int main() {
	init();
	vuln();
}

