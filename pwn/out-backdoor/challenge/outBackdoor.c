#include <stdio.h>

void buffer_init() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
}

int main(void) {
	char feature[16];

	buffer_init();
	printf("\nFool me once, shame on you. Fool me twice, shame on me.\n");
	printf("\nSeriously though, what features would be cool? Maybe it could play a song?\n");

	gets(feature);
}

void outBackdoor() {
	  printf("\n\nW...w...Wait? Who put this backdoor out back here?\n");
	  system("/bin/sh");
}