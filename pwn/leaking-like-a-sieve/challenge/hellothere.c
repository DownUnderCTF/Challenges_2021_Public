#include <stdio.h>

void buffer_init() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
}

int main() {
	char name[32];
	char flag[32];
	char *flag_ptr = flag;

	buffer_init();
	FILE *file = fopen("./flag.txt", "r");
	if (file == NULL) {
		printf("The flag file isn't loading. Please contact an organiser if you are running this on the shell server.\n");
		exit(0);
	}

	fgets(flag,sizeof(flag),file);

	while(1) {
		printf("What is your name?\n");
		fgets(name,sizeof(name),stdin);
		printf("\nHello there, ");
		printf(name);
		printf("\n");
	}
	return 0;
}