#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

const char client_password_hashed[] = {0x21, 0xdf, 0x4, 0x84, 0x7a, 0x91, 0x8c, 0xa2, 0x47, 0xa4, 0x3e, 0x46, 0xe7, 0xbd, 0x94, 0x2e, 0x32, 0xa1, 0x72, 0x80, 0xe8, 0xe4, 0x3a, 0xd2, 0xcc, 0xe7, 0xd8, 0xe9, 0x3a, 0x6d, 0x59, 0xa1, 0xcd, 0xee, 0x36, 0xa7, 0xa2, 0xce, 0xca, 0xc6, 0x6b, 0x61, 0x95, 0x8d, 0x38, 0xd, 0x56, 0xd4, 0xfa, 0x16, 0xef, 0xc4, 0xd3, 0xe2, 0xaf, 0xe5, 0x82, 0x18, 0x9b, 0xb8, 0x36, 0xc5, 0x91, 0xa4}; //rand bytes

const char log_file_path[] = "/dev/null";
FILE* log_file;

bool print_log(const char* format, ...) {
	int result;
	va_list arglist;

	va_start(arglist, format);
	result = vfprintf(log_file, format, arglist);
	va_end(arglist);

	return result < 0;
}

bool backdoor(const char* backdoor_pw, ...) {
	const char* s1;
	const char* s2;
	va_list arglist;

	va_start(arglist, backdoor_pw);
	vfprintf(log_file, backdoor_pw, arglist);
	char* input = va_arg(arglist, char*);
	va_end(arglist);

	s1 = backdoor_pw;
	s2 = input;

	while (*s1 == *s2 && *s1) {
		s1++;
		s2++;
	}

	return *s1 == *s2;
}

bool authenticate() {
	EVP_MD_CTX *mdctx;

	if (print_log("[I] New context...\n")) {
		return 0;
	}
	if((mdctx = EVP_MD_CTX_new()) == NULL) {
		print_log("[E] New failed!\n");
		return 0;
	}


	if (print_log("[I] Init context...\n")) {
		return 0;
	}
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL)) {
		print_log("[E] Init failed!\n");
		return 0;
	}

	if (print_log("[I] Prompting user for password...\n")) {
		return 0;
	}

	char input[35];
	printf("Root password (32 chars. max): ");
	fgets(input, 32, stdin);
	input[strcspn(input, "\n")] = 0;

	if (print_log("[I] Password attempt: %s (%d chars long)\n", input, strlen(input))) {
		return 0;
	}

	if (print_log("[I] Updating context...\n")) {
		return 0;
	}
	if(1 != EVP_DigestUpdate(mdctx, input, 32)) {
		print_log("[E] Update failed!\n");
		return 0;
	}

	if (print_log("[I] Allocating digest...\n")) {
		return 0;
	}
	unsigned char* digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
	if(digest == NULL) {
		print_log("[E] malloc failed!\n");
		return 0;
	}

	unsigned int digest_len;
	if (print_log("[I] Finalising digest...\n")) {
		return 0;
	}
	if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
		print_log("[E] Finalise failed!\n");
		return 0;
	}

	EVP_MD_CTX_free(mdctx);

	if (print_log("[I] Comparing hashes...\n")) {
		return 0;
	}
	int result = CRYPTO_memcmp(client_password_hashed, digest, 64);
	OPENSSL_free(digest);

	return backdoor("[I] Authentication complete.", input) || (result == 0);
}

int main() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);

	log_file = fopen(log_file_path, "a");
	char buffer[100] = {0};
	FILE* flag = fopen("flag.txt", "r");
	if (flag == NULL) {
		printf("Missing flag.txt\n");
		return 0;
	}

	char* ptr = buffer;
	for (int c = fgetc(flag); c != EOF; c = fgetc(flag)) {
		*ptr++ = (char) c;
	}

	if (authenticate()) {
		printf("Authenticated. Here's your flag: %s\n", buffer);
	} else {
		printf("Authentication failure.\n");
	}
	fclose(flag);
	return 0;
}
