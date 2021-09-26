# Challenge Overview

We are given a machine to SSH into and a binary. The binary runs as our shell when we SSH into the machine. It looks like some kind of game where our character is denoted by `p` and we can move it around with `hjkl`. We have a score at the top right as well. If the player is familiar with bullet hell games (or used Google to learn what it is) they might have noticed something strange; there are no bullets! It turns out that there are, it's just that they are invisible. The goal of the challenge will be to be reach a certain score, but to do that, you'll need to be able to avoid the bullets, and to do that, you'll need to know where the bullets are. As we'll see, the bullets are deterministically generated and the entire game can be simulated and solved offline to figure out a winning sequence of moves which we can then copy and paste into the remote server to get the flag.

## Reversing

The binary is relatively easy to understand with Ghidra or IDA's decompilation. It isn't stripped so there are function names which make it easier to navigate through the binary and understand what functions do what. A lot of the code is just ncurses functions which can be safely ignored.

The `play` function looks like this:

```C
void play(void)

{
  int iVar1;
  int *game_state;
  undefined8 window;
  undefined8 uVar2;
  int iStack32;
  
  game_state = (int *)malloc(0x20);
  *game_state = 0xf;
  game_state[1] = 0x21;
  uVar2 = 0x101a38;
  window = newwin(0x29,0x1f,0,0);
  wborder(window,0,0,0,0,0,0,0,0,uVar2);
  wrefresh(window);
  wtimeout(stdscr);
  iStack32 = 0;
  do {
    iStack32 = iStack32 + 1;
    if (iStack32 % 0x19 == 0) {
      generate_bullets(game_state);
    }
    wclear(window);
    mvprintw(2,0x20,"score: %d\n",game_state[2]);
    update_bullets(window,game_state);
    uVar2 = 0x101b3e;
    iVar1 = wmove(window,game_state[1],*game_state);
    if (iVar1 != -1) {
      uVar2 = 0x101b54;
      winsch(window,0x70);
    }
    wborder(window,0,0,0,0,0,0,0,0,uVar2);
    wmove(stdscr,0,0);
    wrefresh(window);
    iVar1 = wgetch(stdscr);
    if (iVar1 == 0x68) {
      if (1 < *game_state) {
        *game_state = *game_state + -1;
      }
    }
    else {
      if (iVar1 == 0x6a) {
        if (game_state[1] < 0x27) {
          game_state[1] = game_state[1] + 1;
        }
      }
      else {
        if (iVar1 == 0x6b) {
          if (1 < game_state[1]) {
            game_state[1] = game_state[1] + -1;
          }
        }
        else {
          if ((iVar1 == 0x6c) && (*game_state < 0x1d)) {
            *game_state = *game_state + 1;
          }
        }
      }
    }
    game_state[2] = game_state[2] + 1;
    if (0x538 < game_state[2]) {
      win();
    }
  } while( true );
}
```

We assume the chunk of 32 byte memory allocated at the start holds the game state since it is used in almost every branch of execution. Observing its use even further, we can see that the first two fields of the game state struct are integers that hold the player's current x and y positions. Towards the end of the `play` function, we see an if-block that calls the `win` function if `game_state[2]` is greater than 1336. In each iteration of the while loop, this value is also incremented. We conclude that this holds our score, and to get the flag we'll need to get a score of 1337.

## Bullet Generation

The important part of the binary is how it generates the bullets. There is a very suspiciously named function `generate_bullets` which sounds like it might be responsible for that:

```C
void generate_bullets(long game_state)

{
  int r;
  uint s;
  int r2;
  int *bullet;
  undefined4 *bullet2;
  uint r_;
  int num_bullets;
  int i;
  int j;
  int k;
  int l;
  int ii;
  void *bullets;
  
  num_bullets = (int)*(undefined8 *)(game_state + 0x18);
  if (*(long *)(game_state + 0x10) == 0) {
    bullets = calloc(0x46,8);
  }
  else {
    bullets = (void *)reallocarray(*(undefined8 *)(game_state + 0x10),(long)(num_bullets + 0x23),8);
  }
  r = rand();
  r_ = (uint)(r >> 0x1f) >> 0x1e;
  s = r + r_ & 3;
  r = s - r_;
  if (s == r_) {
    for (i = 0; i < 0x23; i = i + 1) {
      bullet = (int *)malloc(0x10);
      r = rand();
      *bullet = r % 0x1d + 1;
      r = rand();
      bullet[1] = r % 0xd + 1;
      bullet[2] = 0;
      bullet[3] = 1;
      *(int **)((long)num_bullets * 8 + (long)bullets) = bullet;
      num_bullets = num_bullets + 1;
    }
  }
  else {
    if (r == 1) {
      for (j = 1; j < 0x23; j = j + 1) {
        bullet2 = (undefined4 *)malloc(0x10);
        s = rand();
        if ((s & 1) == 0) {
          *bullet2 = 1;
          bullet2[2] = 1;
        }
        else {
          *bullet2 = 0x1d;
          bullet2[2] = 0xffffffff;
        }
        bullet2[1] = j;
        bullet2[3] = 1;
        *(undefined4 **)((long)num_bullets * 8 + (long)bullets) = bullet2;
        num_bullets = num_bullets + 1;
      }
    }
    else {
      if (r == 2) {
        r = rand();
        r2 = rand();
        for (k = 1; k < 0x1e; k = k + 1) {
          if ((k != r % 0x1d + 1) && (k != r2 % 0x1d + 1)) {
            bullet = (int *)malloc(0x10);
            *bullet = k;
            bullet[1] = 1;
            bullet[2] = 0;
            bullet[3] = 1;
            *(int **)((long)num_bullets * 8 + (long)bullets) = bullet;
            num_bullets = num_bullets + 1;
          }
        }
      }
      else {
        if (r == 3) {
          for (l = 0; l < 4; l = l + 1) {
            r = rand();
            r2 = rand();
            for (ii = 0; ii < 8; ii = ii + 1) {
              bullet = (int *)malloc(0x10);
              *bullet = r % 0x1d + 1;
              bullet[1] = r2 % 0x27 + 1;
              switch(ii) {
              case 0:
                bullet[2] = 1;
                bullet[3] = 0;
                break;
              case 1:
                bullet[3] = 1;
                bullet[2] = bullet[3];
                break;
              case 2:
                bullet[2] = 0;
                bullet[3] = 1;
                break;
              case 3:
                bullet[2] = -1;
                bullet[3] = 1;
                break;
              case 4:
                bullet[2] = -1;
                bullet[3] = 0;
                break;
              case 5:
                bullet[3] = -1;
                bullet[2] = bullet[3];
                break;
              case 6:
                bullet[2] = 0;
                bullet[3] = -1;
                break;
              case 7:
                bullet[2] = 1;
                bullet[3] = -1;
              }
              *(int **)((long)num_bullets * 8 + (long)bullets) = bullet;
              num_bullets = num_bullets + 1;
            }
          }
        }
      }
    }
  }
  *(void **)(game_state + 0x10) = bullets;
  *(long *)(game_state + 0x18) = (long)num_bullets;
  return;
}
```

Looking through the if-else blocks, we can see that there are a few different logics for generating bullets. A common thing we see is a 16 byte chunk being allocated. `bullet[2]` and `bullet[3]` always contain small values like `-1`, `0`, `1` while `bullet[0]` and `bullet[1]` contain larger values between `1` and `30`, and `1` and `40`. The bullet struct looks something like

```C
struct bullet {
    int x, y;
    int dx, dy;
};
```

so this gives us an idea of where the bullets start, and where they move towards (this can also be confirmed by looking at the `update_bullets` function which uses these values as we expect).

Most importantly, we note that these values are all decided by `rand` which is a libc function that provides "random" numbers. These numbers are not truly random however, and if the randomness was seeded by a predictable seed, we can easily predict what the random numbers will be. At the very start of the `main` function, we see a call to `srand(0)`, so the seed is a known fixed value! Since we know the seed, we can easily simulate the random number generation and hence the bullet generation.

## Winning the Game

To ensure our simulation is in sync with the server's, we need to be careful and make sure to call `rand` whenever the binary does. We can find all references to `rand` to help with this.

Since we are only interested in finding a sequence of winning moves, we can modify things like how fast things move, etc. to give us an easier time winning the game if we decide to play it manually.

There isn't much left to do other than carefully implementing the generation logic and maybe an interface to play the game. Since the win score is only 1337 and you get one point every move you make, it's very reasonable to play the game manually and record the sequence of moves you made. Hopefully it's a satisfying result :)

# Playthrough Video

Here is a recording of me manually playing the game and reaching a score of 1337. The solve script which simulates the game records the input keys and prints it at the end, so to get the flag on the remote server, you can copy and paste this string to instantly simulate the moves.

![playthrough.gif](./playthrough.gif)

If bullet hell games aren't your thing, check out this [amazing alternative solution](https://gist.github.com/uint0/f357856d4f386dd5233daa7408b0f01a) by a reviewer which implements an agent to win the game dynamically.
