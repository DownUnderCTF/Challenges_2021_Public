#include <stdio.h>
#include <string.h>

char* flag = "D\0U\0C\0T\0F\0{\0s\0t\0r\0i\0n\0g\0e\0n\0t\0_\0s\0t\0r\0i\0n\0g\0s\0_\0s\0t\0r\0i\0n\0g\0}";

int main() {
	char input[70];
	printf("flag? ");
	fgets(input, 70, stdin);
	for(int i = 0; i < strlen(input) - 1; i++) {
		if(input[i] != flag[2*i]) {
			puts("wrong!");
			return -1;
		}
	}
	puts("correct!");
	return 0;
}
