from flask import Flask
import threading
import os


app_shut = Flask(__name__)
port=5003

@app_shut.route("/shutdown/")
def shut():
    print("shutdown by the server")
    os._exit(1)


def start(host):
    return threading.Thread(target= lambda: app_shut.run(host=host,port=port,debug=False,threaded=True))