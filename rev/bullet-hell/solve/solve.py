from blessed import Terminal
from ctypes import *
from time import sleep

DIED = 0
WIN_SCORE = 1337
GAME_WIDTH = 30
GAME_HEIGHT = 40
WHEN_MORE_BULLETS = 25
NUM_MORE_BULLETS = 35
PLAYER_CHAR = 'p'
BULLET_CHAR = 'x'

def generate_bullets(game_state, rand):
    t = rand() % 4
    if t == 0:
        for i in range(NUM_MORE_BULLETS):
            bullet_x = 1 + (rand() % (GAME_WIDTH - 1))
            bullet_y = 1 + (rand() % (GAME_HEIGHT//3))
            bullet_dx = 0
            bullet_dy = 1
            game_state['bullets'].append((bullet_x, bullet_y, bullet_dx, bullet_dy))
    elif t == 1:
        for i in range(1, NUM_MORE_BULLETS):
            if rand() % 2 == 0:
                bullet_x = 1
                bullet_dx = 1
            else:
                bullet_x = GAME_WIDTH - 1
                bullet_dx = -1
            bullet_y = i
            bullet_dy = 1
            game_state['bullets'].append((bullet_x, bullet_y, bullet_dx, bullet_dy))
    elif t == 2:
        safe1 = 1 + rand() % (GAME_WIDTH - 1)
        safe2 = 1 + rand() % (GAME_WIDTH - 1)
        for i in range(1, GAME_WIDTH):
            if i in [safe1, safe2]:
                continue
            bullet_x = i
            bullet_y = 1
            bullet_dx = 0
            bullet_dy = 1
            game_state['bullets'].append((bullet_x, bullet_y, bullet_dx, bullet_dy))
    elif t == 3:
        for _ in range(NUM_MORE_BULLETS//8):
            center_x = 1 + rand() % (GAME_WIDTH - 1)
            center_y = 1 + rand() % (GAME_HEIGHT - 1)
            for i in range(8):
                bullet_dx = [1, 1, 0, -1, -1, -1, 0, 1][i]
                bullet_dy = [0, 1, 1, 1, 0, -1, -1, -1][i]
                game_state['bullets'].append((center_x, center_y, bullet_dx, bullet_dy))

def print_game(game_state, term):
    board = [list('+' + '-' * (GAME_WIDTH - 1) + '+')]
    for _ in range(GAME_HEIGHT):
        board.append(list('|' + ' ' * (GAME_WIDTH - 1) + '|'))
    board.append(list('+' + '-' * (GAME_WIDTH - 1) + '+'))
    board[game_state['player_y']][game_state['player_x']] = term.on_blue(PLAYER_CHAR)
    for bullet in game_state['bullets']:
        bullet_x, bullet_y, _, _ = bullet
        board[bullet_y][bullet_x] = term.on_orange(BULLET_CHAR)
    out = '\n'.join(''.join(r) for r in board)
    print(out)
    print(term.move(2, GAME_WIDTH + 5) + term.blue(f'score: {game_state["score"]}'))

def update_bullets(game_state):
    for i in range(len(game_state['bullets'])):
        bullet_x, bullet_y, bullet_dx, bullet_dy = game_state['bullets'][i]

        if bullet_x == game_state['player_x'] and bullet_y == game_state['player_y']:
            return DIED

        bullet_x += bullet_dx
        bullet_y += bullet_dy
        game_state['bullets'][i] = (bullet_x, bullet_y, bullet_dx, bullet_dy)

        if bullet_x < 1 or bullet_x > GAME_WIDTH - 1 or bullet_y < 1 or bullet_y > GAME_HEIGHT - 1:
            game_state['bullets'][i] = None

    game_state['bullets'] = [b for b in game_state['bullets'] if b is not None]


def simulate(rand, save_game):
    MOVES = ''

    game_state = {
        'player_x': GAME_WIDTH // 2,
        'player_y': int(GAME_HEIGHT / 1.2),
        'score': 0,
        'bullets': []
    }

    clock = 0
    term = Terminal()
    with term.cbreak():
        while 1:
            clock += 1
            if clock % WHEN_MORE_BULLETS == 0:
                generate_bullets(game_state, rand)

            print(term.home + term.clear, end='')
            died = update_bullets(game_state)
            if died == DIED:
                print('died! moves: ' + MOVES)
                return
            print_game(game_state, term)

            if clock - 1 < len(save_game):
                player_move = save_game[clock - 1]
                sleep(0.08)
            else:
                player_move = term.inkey(0.1)
            player_x = game_state['player_x']
            player_y = game_state['player_y']
            if player_move in ['h', 'a'] and 1 < player_x:
                game_state['player_x'] -= 1
            elif player_move in ['j', 's'] and player_y < GAME_HEIGHT - 1:
                game_state['player_y'] += 1
            elif player_move in ['k', 'w'] and 1 < player_y:
                game_state['player_y'] -= 1
            elif player_move in ['l', 'd'] and player_x < GAME_WIDTH - 1:
                game_state['player_x'] += 1
            else:
                player_move = 'x' # filler to skip time

            MOVES += player_move
            game_state['score'] += 1
            if game_state['score'] >= WIN_SCORE:
                print('won! moves: ' + MOVES)
                return

libc = CDLL('/lib/libc.so.6')
libc.srand(0)
saved_game = 'kjlhhkljhkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxkxxxxxjjxjxjxjxjxjxjxjxjxjxhxxhxxxxxxlxxxxkxxxjxxxxhxhxhxhxxlxlxxxlxlxxxlxxxxhxxhxlxlxhxxxhxkxxlxjxxxxhxxxjjklxxxlxkxlkxlxxxlxxxxlxlxlxlxlxlxjxjxjxjxjxlxxkxkxkxkxlxxxxhjxhxhxjxxhxkxhxhxxxxlxxxjxjxjxjxxhxhxxxxxxlxxxxxxxhxhxhxxlxxhxxxxlxxxxxxxxxxxxxxxxxxxxkxxlxxxxhxxxhxxxxxxxxxxxxxjxxlxxkhxjxxxhxxxxxxlxlxlxlxlxlxxxxxxxxxxxhxhxxhxxxxxxxxhxhxhxxxxxxxxhxhxxxkxkhxxxxxxxxxxxxxjxxxxxhxxxxxlxlxlxxxxjxxxxxxxlxlxxxxxxxxhxxlxxhxhxxxxxxxlxlxlxlxxxxxhxhxxhxxhxxxxxxkxxlxxxxlxxxkxjxlxxxlxxxlxlxlxlxxhxhxhxhxhxhxhxhxhxxxxxxxxxxxxxxxxxxkxkjxxxkxxxklkxkxlxlxlxlxlxlxlxlxlxlxkxkhjxjhxhjxhjxjhxlxlxlxlxxxxhxxxxjhxjhxxxxlxxxxxxlxxhxhxhxhxhxhxxxxxxjxxxxxxhxjjxkxkxkxkxkxkxxxlxlxlxlxxxxhxjxhjxxxxxxhxxhxhxxlxxhxhxxlxxxlxlxlxlxlxlxxxxxxxxxxxxxxxxxhxhxxxxxxxkxxxxxxxxxxxxxlxlxlxkxxxkxxxxxxxxxxxxxxlxxxxlxxxxlxxhxhxhxhxhxxxxxxjxxxkxxhxxxjxhxjhxxxxxxxkxkxxxlxxxxhxhxhlxxxxlllllllllllxxxxxxkxxxxkxxxkhjhxxjhxhjxjhxhjxhjxhjxjhxhjxhjxhxhxhxhxxxxxxxxxxxxxxhxhxhxxhxhxhxlxlxxlxlxxlxhxhxhxhxlxlxlxlxxlxxkxxxxxklxxxxlxhxxlxlxlxxxxlxlxxxhxxhxxxkxkxxxxkxxxxxxxlxlxlxlxxxhxhxhxhxxkxxhxxhxkxhxxxxxxxkxlxxxxxxxlxlxlxlxlxlxlxlxxxxxxjhxxxlxxxxxxxxxjxxjxxxxxjxxxxxhxxxhxxxhxhxxxxxhxxxxhjxxxxhxxxxxxxxhxxlxxxxxxxxjxxxxlxlxlxxhxxxhxxxxxxxxxhxhxhxhxhxhxhxhxxxhxxxxxxlxlxxxxlxxxlxxxxhxxxxxxxxxxxxxxxxlxxxlxxxxhxxxxxxxlxlxlxlxlxxxxxxxhxxxxxxxxxxxxxxxxxxxxhxhxxxlxxxxxxxxxxxhxhxxhxxlxxlxlxxjlxxxxhxxhxxxkxxlxlxjxjxjkxxxkxxxhxhxhxxlxxlxkxxxlxxxlxlxlxlxlxkxxlxxxxxxxxxhxxxkxlxlxlxlxxlxxxhxxxxhxhxhxhxhxhxhxhxhhhxhxxxxxxxxxlxkxkxhxxxxxxxkxjxjxjxjxxxhxkxkxkxxxxxxxxxxjxjlxjxxxxxxxlxxxxjxlxxlxxkxjxxxxxhxxxjxxhxxlkxklxxxljxxxxlxxxxxxxxkxkxxxxxxxxjxjxjxlxxkxkxkxkxxxxxxjxhxxxxxxhxhxhxhxhxxxlxxljxxxxxxlxlxlxkxkxkxkxhxxjhxxjhxhxxxxlxxjxjxxlxxkxkxxjxhxxxxxkxhxhxxhxkxlxjxxljxlxxxxhxhxhxhxlxlxxljxxxxxxxkxkxhxhxhxxxxlxlxjxlxkxxxxxhxxjxxxklxxxlxjxjxjxxxxlxxkxkxkxxhxhxhxhxxxjxljxlxlxxxxkxkxhxjjxjxlxxkxxxxxxxkhxhxxxxxkxxxxxxxlxxxxhxhxxxkxxkxkxxjlxlxjxlxxxlxlxkxxxkxkxkxjxjxjxjxjxxlxlxlxlxlxlxxxxxkhxjxhjxhxxlxlxxxxxxlxxxhxxxxxxxxjxxxxlxxxxxxxkxhxxhxhxhxxxhxxlxxxxkxxxxlxhxjxhxjxhxhxhxhxhxhxhxxxxxxxxjxlxhxhxhxhxhxhxxxxxxxxxxxxlxxlxlxxxxxxxxxxxlxxxxxlxlxlxxxxxxxxxxxlxxxxhxhxxxlxlxxxhxhxhxhxxxlxlxlxlxlxxxxkxkxxkhxxjxxxlxxlxxxxxxxhxhxhxhxxxxxxxxxxxxxxlxjxxxxxhxxxxxhxhxxxlxlxlxxxxxlxkhxhxhxhxxlxlxlxlxxxxxxlxlxxxxxxxhxhxhxlxlxxjxxxxkxxhxhxhxhxxxxlxlxlxlxxljxjxlxlxlxlxxxlxxxxxxxxxxjxjxlxxlxxxlxxxhxhxhxhxhxxlxlxlxlxklkkxxxlkhxhxhxxxxxxxhxxxxxxlxkhxhjxhjxhxxxkhxxxxxxxxxhxjxxxjxxhxxxxhxhxhxlxlxlxxkxxxxxxxxxlxxlxlxxlxlxxlxxxhxxxxxxhxhxxjxxkxhxjxxhxjxxkxhxxlxlxlxlxlxlxlxlxlxxl'
# saved_game = ''
simulate(libc.rand, saved_game)
