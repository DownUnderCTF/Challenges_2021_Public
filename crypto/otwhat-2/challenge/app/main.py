from flask import Flask, request, redirect, url_for
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA3_512
from base64 import b64decode
app = Flask(__name__)

with open("secp256r1.key") as f:
    key = ECC.import_key(f.read())
    verifier = DSS.new(key, 'fips-186-3', 'der')

log = []
with open("update.log") as f:
    for event in f:
        log.append(event.split(" "))

@app.route("/update.cgi", methods=['GET', 'POST'])
def update():
    output = (
        "<style>"
        "table, th, td {"
        "    border: 1px solid black;"
        "    border-collapse: collapse;"
        "}"
        "</style>"
    )
    output += (
       f'<form action="{url_for("update")}" method="post">\n'
        '    <label for="url">URL: </label>\n'
       f'    <input type="text" name="url" id="url" required>\n'
        '    <label for="signature">Signature (Base64): </label>\n'
       f'    <input type="text" name="signature" id="signature" required>\n'
        '    <input type="submit" value="Update">'
        '</form>\n'
        '<br>\n'
    )

    if request.method == "POST":
        url = request.form.get('url')
        hash = SHA3_512.new(url.encode('latin1'))
        signature = request.form.get('signature')
        try:
            verifier.verify(hash, b64decode(signature))
            if url.startswith("https://GOODCODE/"):
                output += "Update successful<br>\n"
            elif url.startswith("https://EVILCODE/"):
                output += "Update successful<br>\n"
                output += "<pre>RCE POPPED! You have earned a trophy: Public Private Keys\nDUCTF{27C3 Console Hacking 2010 (PS3 3p1c F41l)}</pre><br>\n"
            else:
                output += "Update failed<br>\n"
        except ValueError as e:
            print(e)
            output += "Invalid signature<br>\n"

    output += "Update audit log:<br>\n"
    output += (
        '<table>\n'
        '    <tr>'
        '        <th>Update URL</th>'
        '        <th>ECDSA signature</th>'
        '    </tr>'
    )
    for event in log:
        output += "    <tr>\n"
        for column in event:
            output +=  "    <td>\n"
            output += f"        {column}\n"
            output +=  "    </td>\n"
        output += "    </tr>\n"
    output += "</table>\n"

    output += '<!-- DEBUG\n'
    if request.method == "POST":
        output += "URL hash: " + SHA3_512.new(url.encode('latin1')).hexdigest() + "\n"
    output += '-->'
    return output


@app.route("/")
def root():
    return redirect(url_for('update'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
