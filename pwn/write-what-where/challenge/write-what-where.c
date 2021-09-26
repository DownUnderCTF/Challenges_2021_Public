#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main() {
	init();

	char where_buf[16];
	long where;
	char what[4];

	puts("write");

	puts("what?");
	read(0, what, 4);

	puts("where?");
	read(0, where_buf, 9);
	where = atoi(where_buf);

	*(int*)where = *(int*)what;

	exit(0);
}
