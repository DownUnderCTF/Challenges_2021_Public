#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "offsets.h"

#define MAX_NUM_CHILDREN 5
#define BLOCK_SIZE 36
#define NUM_NODES 256
#define NUM_ROUNDS 16

struct node {
	unsigned char value;
	struct node** children;
};

typedef struct node node_t;

unsigned int s;

void _srand(unsigned int x) {
	s = x;
}

unsigned int _rand() {
	s = s * 0x9157131 + 0x44799011;
	return s;
}

void init() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
}

node_t* generate(unsigned char* buf) {
	_srand(0x1337);

	node_t** leaves = (node_t**) calloc(MAX_NUM_CHILDREN * NUM_NODES, sizeof(node_t*));
	node_t* root = (node_t*) malloc(sizeof(node_t));
	leaves[0] = root;

	int cur_len = 1;
	int i;

	for(i = 0; i < NUM_NODES; i++) {
		// get head of queue
		node_t* cur = leaves[i];

		int num_children = (_rand() % MAX_NUM_CHILDREN);

		// you are a leaf
		if(num_children == 0) continue;

		// add random number of children to queue
		node_t** children = (node_t**) calloc(num_children, sizeof(node_t*));
		for(int j = 0; j < num_children; j++) {
			node_t* child = (node_t*) malloc(sizeof(node_t));
			children[j] = child;
			leaves[cur_len++] = child;
		}
		cur->children = children;

		// nullify array entry
		leaves[i] = NULL;
	}

	// add values to leaves
	for(i = 0; i < cur_len; i++) {
		if(leaves[i] == NULL) continue;
		leaves[i]->value = buf[_rand() % BLOCK_SIZE];

		// 👀
		/* int c = _rand() % BLOCK_SIZE; */
		/* unsigned int offset = (unsigned int)((long)leaves[i] - (long)root); */
		/* printf("%03d | offset: %04x, value: %d\n", i, offset, c); */
		/* printf("#define OFFSET_FOR_%02d_%d 0x%x\n", c, i, offset); */
	}

	return root;
}

void permute(unsigned char* input, node_t* root) {
	input[0]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_23_216);
	input[1]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_16_500);
	input[2]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_19_19);
	input[3]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_12_37);
	input[4]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_31_271);
	input[5]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_24_284);
	input[6]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_17_281);
	input[7]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_22_482);
	input[8]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_13_257);
	input[9]  = *(unsigned char*)((unsigned long)root + OFFSET_FOR_18_127);
	input[10] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_25_24);
	input[11] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_30_30);
	input[12] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_09_417);
	input[13] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_02_17);
	input[14] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_11_259);
	input[15] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_04_412);
	input[16] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_33_154);
	input[17] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_26_302);
	input[18] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_03_117);
	input[19] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_08_121);
	input[20] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_05_377);
	input[21] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_10_294);
	input[22] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_27_132);
	input[23] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_32_166);
	input[24] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_21_104);
	input[25] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_14_402);
	input[26] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_35_161);
	input[27] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_28_316);
	input[28] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_07_263);
	input[29] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_00_219);
	input[30] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_15_503);
	input[31] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_20_260);
	input[32] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_29_172);
	input[33] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_34_414);
	input[34] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_01_301);
	input[35] = *(unsigned char*)((unsigned long)root + OFFSET_FOR_06_258);
}

unsigned char m2(unsigned char b) {
	return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void mix_column(unsigned char* input, int idxs[]) {
	unsigned char b0, b1, b2, b3, b4, b5;
	unsigned char d0, d1, d2, d3, d4, d5;
	b0 = input[idxs[0]];
	b1 = input[idxs[1]];
	b2 = input[idxs[2]];
	b3 = input[idxs[3]];
	b4 = input[idxs[4]];
	b5 = input[idxs[5]];
	d0 = b0 ^ m2(b0) ^ b2 ^ m2(b2) ^ (m2(b4));
	d1 = b1 ^ m2(b1) ^ b3 ^ m2(b3) ^ (m2(b5));
	d2 = m2(b0) ^ b4;
	d3 = m2(b1) ^ b5;
	d4 = b0 ^ m2(b0) ^ m2(b2);
	d5 = b1 ^ m2(b1) ^ m2(b3);
	input[idxs[0]] = d0;
	input[idxs[1]] = d1;
	input[idxs[2]] = d2;
	input[idxs[3]] = d3;
	input[idxs[4]] = d4;
	input[idxs[5]] = d5;
}

void mix(unsigned char* input) {
	int c0[6] = {0, 1, 2, 6, 12, 18};
	int c1[6] = {3, 4, 5, 11, 17, 23};
	int c2[6] = {7, 8, 9, 13, 14, 15};
	int c3[6] = {10, 16, 22, 28, 29, 35};
	int c4[6] = {19, 20, 24, 25, 26, 30};
	int c5[6] = {21, 27, 31, 32, 33, 34};
	mix_column(input, c0);
	mix_column(input, c1);
	mix_column(input, c2);
	mix_column(input, c3);
	mix_column(input, c4);
	mix_column(input, c5);
}

void die() {
	puts("Incorrect :(");
	exit(1);
}

unsigned char final[BLOCK_SIZE] = {0x0f, 0x4f, 0x73, 0x3c, 0x41, 0xc6, 0xa4, 0xaf, 0xb4, 0x41, 0xd6, 0x65, 0xc8, 0x99, 0xaa, 0xb3, 0x6c, 0x99, 0x61, 0x3c, 0x4e, 0xdd, 0x70, 0x46, 0x15, 0x66, 0x3c, 0x1b, 0x7f, 0x16, 0xa6, 0x6f, 0x23, 0x13, 0x12, 0x6e};

int main() {
	init();
	unsigned char input[BLOCK_SIZE+1];

	printf("What's the flag?: ");
	fgets((char*)input, sizeof(input), stdin);
	if(strlen((char*)input) != BLOCK_SIZE) {
		die();
	}

	for(int i = 0; i < NUM_ROUNDS; i++) {
		mix(input);
		node_t* root = generate(input);
		permute(input, root);
	}

	for(int i = 0; i < BLOCK_SIZE; i++) {
		if(input[i] != final[i]) {
			die();
		}
	}

	puts("Correct! :)");
	exit(0);
}
