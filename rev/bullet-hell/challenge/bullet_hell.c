#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ncurses.h>

#define WIN_SCORE 1337
#define GAME_WIDTH 30
#define GAME_HEIGHT 40
#define WHEN_MORE_BULLETS 25
#define NUM_MORE_BULLETS 35
#define PLAYER_CHAR 'p'
#define BULLET_CHAR 'x'

typedef struct {
	int x, y;
	int dx, dy;
} bullet_t;

typedef struct {
	int player_x, player_y;
	int score;
	bullet_t** bullets;
	size_t bullets_len;
} game_t;

void generate_bullets(game_t* game_state) {
	bullet_t** bullets;

	// get current number of bullets
	int curr_num_bullets = game_state->bullets_len;
	if(game_state->bullets) {
		bullets = (bullet_t**) reallocarray(game_state->bullets, curr_num_bullets + NUM_MORE_BULLETS, sizeof(bullet_t*));
	} else {
		bullets = (bullet_t**) calloc(2*NUM_MORE_BULLETS, sizeof(bullet_t*));
	}

	int type = rand() % 4;

	if(type == 0) {
		// random barrage from above
		for(int i = 0; i < NUM_MORE_BULLETS; i++) {
			bullet_t* bullet = (bullet_t*) malloc(sizeof(bullet_t));
			bullet->x = 1 + rand() % (GAME_WIDTH - 1);
			bullet->y = 1 + rand() % (GAME_HEIGHT/3);
			bullet->dx = 0;
			bullet->dy = 1;
			bullets[curr_num_bullets++] = bullet;
		}
	} else if(type == 1) {
		// barrage from left and right
		for(int i = 1 ; i < NUM_MORE_BULLETS; i++) {
			bullet_t* bullet = (bullet_t*) malloc(sizeof(bullet_t));
			if(rand() % 2 == 0) {
				bullet->x = 1;
				bullet->dx = 1;
			} else {
				bullet->x = GAME_WIDTH - 1;
				bullet->dx = -1;
			}
			bullet->y = i;
			bullet->dy = 1;
			bullets[curr_num_bullets++] = bullet;
		}
	} else if(type == 2) {
		// barrage from above, except for one safe position
		int safe1 = 1 + rand() % (GAME_WIDTH - 1);
		int safe2 = 1 + rand() % (GAME_WIDTH - 1);
		for(int i = 1; i < GAME_WIDTH; i++) {
			if(i == safe1 || i == safe2) continue;
			bullet_t* bullet = (bullet_t*) malloc(sizeof(bullet_t));
			bullet->x = i;
			bullet->y = 1;
			bullet->dx = 0;
			bullet->dy = 1;
			bullets[curr_num_bullets++] = bullet;
		}
	} else if(type == 3) {
		// circular blast from a few random points
		for(int j = 0; j < NUM_MORE_BULLETS / 8; j++) {
			int center_x = 1 + rand() % (GAME_WIDTH - 1);
			int center_y = 1 + rand() % (GAME_HEIGHT - 1);
			for(int i = 0; i < 8; i++) {
				bullet_t* bullet = (bullet_t*) malloc(sizeof(bullet_t));
				bullet->x = center_x;
				bullet->y = center_y;
				switch(i) {
					case 0:
						bullet->dx = 1;
						bullet->dy = 0;
						break;
					case 1:
						bullet->dx = bullet->dy = 1;
						break;
					case 2:
						bullet->dx = 0;
						bullet->dy = 1;
						break;
					case 3:
						bullet->dx = -1;
						bullet->dy = 1;
						break;
					case 4:
						bullet->dx = -1;
						bullet->dy = 0;
						break;
					case 5:
						bullet->dx = bullet->dy = -1;
						break;
					case 6:
						bullet->dx = 0;
						bullet->dy = -1;
						break;
					case 7:
						bullet->dx = 1;
						bullet->dy = -1;
						break;
				}
				bullets[curr_num_bullets++] = bullet;
			}
		}
	}

	game_state->bullets = bullets;
	game_state->bullets_len = curr_num_bullets;
}

void die() {
	endwin();
	puts("You lose :(");
	exit(1);
}

void win() {
	endwin();
	FILE* fp = fopen("flag.txt", "r");
	char flag[255];
	fgets(flag, 255, fp);
	printf("%s", flag);
	exit(0);
}

void update_bullets(WINDOW* window, game_t* game_state) {
	int i = 0;
	if(!game_state->bullets) return;
	for(i = 0; i < game_state->bullets_len; i++) {
		bullet_t* bullet = game_state->bullets[i];
		if(!bullet) continue;

		// print bullet
		// mvwinsch(window, bullet->y, bullet->x, BULLET_CHAR);

		// check for collision with player
		if(bullet->x == game_state->player_x && bullet->y == game_state->player_y) {
			die();
		}

		// update bullet position
		bullet->x += bullet->dx;
		bullet->y += bullet->dy;

		// check if the bullet is out of the game
		if(bullet->x < 1 || bullet->x > GAME_WIDTH - 1 || bullet->y < 1 || bullet->y > GAME_HEIGHT - 1) {
			free(bullet);
			game_state->bullets[i] = NULL;
		}
	}

	// remove null bullets
	bullet_t** bullets = (bullet_t**) calloc(i, sizeof(bullet_t*));
	int k = 0;
	for(int j = 0; j < i; j++) {
		if(game_state->bullets[j]) {
			bullets[k++] = game_state->bullets[j];
		}
	}
	free(game_state->bullets);
	game_state->bullets = bullets;
}

int play() {
	game_t* game_state = (game_t*) malloc(sizeof(game_t));
	game_state->player_x = GAME_WIDTH / 2;
	game_state->player_y = GAME_HEIGHT / 1.2;

	WINDOW* window = newwin(GAME_HEIGHT+1, GAME_WIDTH+1, 0, 0);
	box(window, 0, 0);
	wrefresh(window);
	timeout(1000);

	int clock = 0;
	while(1) {
		clock++;
		if(clock % WHEN_MORE_BULLETS == 0) {
			generate_bullets(game_state);
		}

		wclear(window);
		mvprintw(2, GAME_WIDTH + 2, "score: %d\n", game_state->score);
		update_bullets(window, game_state);
		mvwinsch(window, game_state->player_y, game_state->player_x, PLAYER_CHAR);
		box(window, 0, 0);
		move(0, 0);
		wrefresh(window);

		int inp = getch();
		if(inp == 'h') {
			if(game_state->player_x > 1) {
				game_state->player_x--;
			}
		} else if(inp == 'j') {
			if(game_state->player_y < GAME_HEIGHT - 1) {
				game_state->player_y++;
			}
		} else if(inp == 'k') {
			if(game_state->player_y > 1) {
				game_state->player_y--;
			}
		} else if(inp == 'l') {
			if(game_state->player_x < GAME_WIDTH - 1) {
				game_state->player_x++;
			}
		}

		game_state->score++;
		if(game_state->score >= WIN_SCORE) {
			win();
		}
	}
}

int main() {
	srand(0);
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	printw("Enter a key to start...\n");
	getch();
	refresh();
	play();
}

