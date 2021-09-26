from flask import Flask, request
import jwt, time, os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

private_key = open('priv').read()
public_key = open('pub').read()
flag = open('flag.txt').read()

@app.route("/get_token")
def get_token():
    return jwt.encode({'admin': False, 'now': time.time()}, private_key, algorithm='RS256')

@app.route("/get_flag", methods=['POST'])
def get_flag():
  try:
    payload = jwt.decode(request.form['jwt'], public_key, algorithms=['RS256'])
    if payload['admin']:
      return flag
  except:
    return ":("

@app.route("/")
def sauce():
  return "<pre>%s</pre>" % open(__file__).read()

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000)
