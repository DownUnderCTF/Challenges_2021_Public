from maze_data import MAZE_WIDTH, MAZE_HEIGHT, DOTS_DATA, MAZE_DATA
from itertools import permutations

def prod(arr, n):
    p = 1
    for a in arr:
        p *= a
        p %= n
    return p

"""
1. figure out the correct order of dots to get the goal to be 0xff
2. bfs to find path to each dot in the correct order
"""

MOVES = {
    'WEST': (-1, 'h', 0b0001),
    'EAST': (1,  'l', 0b0100),
    'SOUTH': (MAZE_WIDTH, 'j', 0b0010),
    'NORTH': (-MAZE_WIDTH, 'k', 0b1000)
}

def get_neighbours(maze, pos):
    neighbours = []
    for m in MOVES:
        dpos, move_char, data_mask = MOVES[m]
        new_pos = pos + dpos
        if 0 <= new_pos < len(maze) and (maze[pos] & data_mask == 0):
            neighbours.append((new_pos, move_char))
    return neighbours

def bfs(maze, start, goal):
    visited = {start}
    parents = {}
    Q = [start]
    while len(Q):
        v = Q.pop(0)
        if v == goal:
            return reconstruct_path(parents, goal)
        for neighbour, move in get_neighbours(maze, v):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            parents[neighbour] = (v, move)
            Q.append(neighbour)

def reconstruct_path(parents, goal):
    path = []
    moves = []
    while goal in parents:
        moves.insert(0, parents[goal][1])
        path.insert(0, goal)
        goal = parents[goal][0]
    path.insert(0, goal)
    return path, ''.join(moves)

def get_dot_locations_and_idx(maze):
    dot_locations = []
    for i, p in enumerate(maze):
        if p & 0b10000000:
            x = i % MAZE_WIDTH
            y = i // MAZE_HEIGHT
            dot_idx = (p >> 4) & 0b111
            dot_locations.append((x, y))
    return dot_locations

# naive but feasible
def get_dot_ordering(dot_data_):
    dot_data = list(enumerate(dot_data_))
    for perm in permutations(dot_data):
        state = 0
        for _, z in perm:
            state &= (z >> 8)
            state ^= (z & 0xff)
        if state == 0xff:
            return [i for i, _ in perm]

dot_locs = get_dot_locations_and_idx(MAZE_DATA)
win_dot_ordering = get_dot_ordering(DOTS_DATA)

print('dot_locations:', dot_locs)
print('dot_ordering:', win_dot_ordering)

checkpoints = [dot_locs[i] for i in win_dot_ordering]
checkpoints = [x + MAZE_WIDTH*y for x, y in checkpoints]
win_moves = ''
cur_pos = 0
for c in checkpoints:
    _, moves = bfs(MAZE_DATA, cur_pos, c)
    cur_pos = c
    win_moves += moves + 'x'

print('win_moves:', win_moves)

key = [win_moves[i:i+81] for i in range(0, len(win_moves)-2, 81)]
key = [prod(w.encode(), 0xff) for w in key]
print('key:', list(key))

ct = [184, 64, 13, 26, 252, 53, 44, 60, 181, 51, 222, 15, 102, 86, 225, 60, 179, 244, 161, 3, 99, 198, 139, 217, 105, 244, 215, 157, 161, 163, 216, 244, 48, 247, 150, 164, 240, 237, 200, 234, 153, 108, 162, 113]
flag = bytes([c^k for c,k in zip(ct, key)])
print('flag:', flag.decode())
