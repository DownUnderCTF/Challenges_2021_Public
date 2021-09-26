#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "maze_data.h"

void die() {
	puts("no :<");
	exit(-1);
}

int find(int* arr, int n, int x) {
	for(int i = 0; i < n; i++) {
		if(*(arr+i) == x) {
			return i;
		}
	}
	return -1;
}

int run(char* moves) {
	char c;
	int has_wall, is_dot;
	int win_bits = 0;
	int cur_pos = 0;
	int dots_eaten[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
	int num_dots_eaten = 0;

	while(*moves) {
		switch(*moves++) {
			case 'h':
				has_wall = MAZE_DATA[cur_pos] & 1;
				if(has_wall) die();

				cur_pos -= 1;

				break;
			case 'l':
				has_wall = MAZE_DATA[cur_pos] & 4;
				if(has_wall) die();

				cur_pos += 1;

				break;
			case 'j':
				has_wall = MAZE_DATA[cur_pos] & 2;
				if(has_wall) die();

				cur_pos += MAZE_WIDTH;

				break;
			case 'k':
				has_wall = MAZE_DATA[cur_pos] & 8;
				if(has_wall) die();

				cur_pos -= MAZE_WIDTH;

				break;
			case 'x':
				is_dot = MAZE_DATA[cur_pos] & 128;
				if(!is_dot) die();
				
				int dot_idx = (MAZE_DATA[cur_pos] >> 4) & 7;
				int exists = find(dots_eaten, 8, dot_idx);
				if(exists >= 0) die();

				dots_eaten[num_dots_eaten++] = dot_idx;
				win_bits &= DOTS_DATA[dot_idx] >> 8;
				win_bits ^= DOTS_DATA[dot_idx] & 0xff;

				if(num_dots_eaten == 8) {
					if(win_bits == 0xff) {
						return 1;
					} else {
						die();
					}
				}

				break;
			default:
				die();
		}
	}

	die();
	return 0;
}

char CT[44] = {184, 64, 13, 26, 252, 53, 44, 60, 181, 51, 222, 15, 102, 86, 225, 60, 179, 244, 161, 3, 99, 198, 139, 217, 105, 244, 215, 157, 161, 163, 216, 244, 48, 247, 150, 164, 240, 237, 200, 234, 153, 108, 162, 113};

int main() {
	char moves[3568];
	int n = read(0, moves, 3567);
	moves[n-1] = '\0';

	run(moves);

	puts("yes :>");

	for(int i = 0; i < 44; i++) {
		int k = 1;
		for(int j = 0; j < 81; j++) {
			k *= moves[i*81 + j];
			k %= 0xff;
		}
		printf("%c", k ^ CT[i]);
	}

	puts("");

	return 0;
}
