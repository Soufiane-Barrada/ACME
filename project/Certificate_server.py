from flask import Flask
import threading


app_cert = Flask(__name__)
port=5001
certificate={}

@app_cert.route("/")
def get_cert():
    return "should return certificate"

def start(host,certif,key):
    return threading.Thread(target= lambda: app_cert.run(host=host,port=port,debug=False,threaded=True,ssl_context=(certif,key)))
