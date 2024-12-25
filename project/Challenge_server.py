from flask import Flask
import threading


app_chal = Flask(__name__)
port=5002
dict={}

@app_chal.route("/.well-known/acme-challenge/<token>")
def challenge(token):
    print("ANSWERING")
    if(token in dict):
        return dict[token]
    return "No such a thing"


def start(host):
    return threading.Thread(target= lambda: app_chal.run(host=host,port=port,debug=False,threaded=True))

def add_token_keyAuth(token,keyAuth):
    dict[token]=keyAuth