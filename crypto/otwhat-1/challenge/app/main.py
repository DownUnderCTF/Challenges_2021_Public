from flask import Flask, request, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_512
from Crypto.Signature import pkcs1_15
from base64 import b64decode, b64encode
app = Flask(__name__)

with open("rsa.key") as f:
    key = RSA.import_key(f.read())

example_url = "https://GOODCODE/"
example_sig = b64encode(pkcs1_15.new(key).sign(SHA3_512.new(example_url.encode()))).decode()


def strcmp(s1: bytes, s2: bytes) -> int:
    for a, b in zip(s1 + b'\0', s2 + b'\0'):
        if a == 0 or a != b:
            break
    return a - b


@app.route("/update.cgi", methods=['GET', 'POST'])
def update():
    output = (
       f'<form action="{url_for("update")}" method="post">\n'
        '    <label for="url">URL: </label>\n'
       f'    <input type="text" name="url" id="url" value="{example_url}" required>\n'
        '    <label for="signature">Signature (Base64): </label>\n'
       f'    <input type="text" name="signature" id="signature" value="{example_sig}" required>\n'
        '    <input type="submit" value="Update">'
        '</form>\n'
        '<br>\n'
    )
    if request.method == "POST":
        result = None

        url = request.form.get('url')
        hash = SHA3_512.new(url.encode('latin1')).digest()
        try:
            signature = b64decode(request.form.get('signature'))
        except:
            output += "Error: Signature parsing error.<br>\n"
        else:
            if len(signature) != 512:
                output += "Error: Incorrect signature length (expected 512 bytes).<br>\n"
            else:
                try:
                    signature = int.from_bytes(signature, "big")
                    if signature <= 1:
                        output += "Error: Invalid signature<br>\n"
                    else:
                        decrypted_signature = pow(signature, key.e, key.n).to_bytes(key.size_in_bytes(), "big")
                        result = strcmp(hash, decrypted_signature[-64:])
                except Exception as e:
                    print(e)
                    output += "Error<br>\n"

                if result == 0:
                    if url.startswith("https://GOODCODE/"):
                        output += "Update successful<br>\n"
                    elif url.startswith("https://EVILCODE/"):
                        output += "Update successful<br>\n"
                        output += "<pre>RCE POPPED! HACK THE PLANET!! DUCTF{https://wiibrew.org/wiki/Signing_bug#L0L_memcmp=strcmp}</pre><br>\n"
                    else:
                        output += "Update failed<br>\n"
                else:
                    output += "Error: Invalid signature<br>\n"

    output += (
        '<!-- DEBUG\n'
        'OEM Key: \n' +
       f'{key.public_key().export_key().decode()}\n'
    )
    if request.method == "POST" and result is not None:
        output += f'\nupdate.c:69:main(): strcmp(hash, &decrypted_signature[512 - 64]) = {result}\n'
    output += '-->'
    return output


@app.route("/")
def root():
    return redirect(url_for('update'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
