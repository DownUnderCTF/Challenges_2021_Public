#include <stdio.h>

void buffer_init() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
}

int main(void) {
	long code = 0;
	char feature[16];
	
	buffer_init();
	printf("\nI'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.\n");
	printf("\nWhat features would you like to see in my app?\n");

	gets(feature);

	if(code == 0xdeadc0de) {
		printf("\n\nMaybe this code isn't so dead...\n");
		system("/bin/sh");
	  }
}