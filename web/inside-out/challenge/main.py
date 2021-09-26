from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from config import LOG_FILE, LOCAL_CIDR, FLAG
from util import is_localhost, get_title, generate_random_ip
import requests
import subprocess
import ipaddress
import sys

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/request")
def send_request():
    url = request.args.get("url")
    if not url:
        return ("<h1>Bad request</h1>", 400)

    # Give some random output for example
    if url == "http://example.com/":
        out = subprocess.run(
            ["ip", "addr"], stdout=subprocess.PIPE).stdout.decode("utf-8")

        return jsonify({
            "status": "success",
            "text": out,
            "status_code": 200,
            "title": "Example",
            "redirect_url": "",
            "hostname": "example.com",
            "port": 80
        })

    # Getting hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""

    # Check if request is sent to localhost
    if hostname and is_localhost(hostname):
        return render_template("blacklist.html", loopback=hostname), 403

    print("Sending request: " + url)

    # Write result to log (the user should be in adm group to write to /var/log)
    with open(LOG_FILE, "a") as f:
        f.write(url + " from " + generate_random_ip() + "\n")

    # Send request
    result = None
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)

    except:
        result = jsonify({"status": "failed"})

    if result:
        return result

    # Look for title
    title = get_title(response.text)

    # Check if redirect
    redirect_url = ""
    if response.is_redirect:
        redirect_url = response.headers["Location"]

    result = {
        "status": "success",
        "text": response.text,
        "status_code": response.status_code,
        "title": title,
        "redirect_url": redirect_url,
        "hostname": hostname,
        "port": parsed_url.port
    }

    return jsonify(result)


@app.route("/admin")
def admin():
    # Accessible by machines in the same local network
    if ("X-Real-Ip" not in request.headers or 
        is_localhost(request.headers["X-Real-Ip"]) or
        ipaddress.ip_address(request.headers["X-Real-Ip"]) in ipaddress.ip_network(LOCAL_CIDR, False)):

        print("Local network request!")
        print(request.headers["X-Real-Ip"])
    else:
        print("Real IP doesn't exist")
        return render_template("forbidden.html"), 403

    # Get last 5 logs
    # Write result to log
    lines=[]
    with open(LOG_FILE, "a+") as f:
        f.seek(0)
        lines=f.readlines()

    return render_template("admin.html", logs = lines[-5:], FLAG = FLAG)


if __name__ == "__main__":
    app.run(host = "0.0.0.0")
