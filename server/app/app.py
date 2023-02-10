import os
import redis
import validators
from base64 import b32encode
from datetime import datetime, timedelta
from flask import Flask, redirect, render_template, request, session, url_for

from util import vt_url_malicious

SERVER_URL = os.getenv("SERVER_URL") or "localhost"
TIMEOUT_MAX = 86400


app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["sitename"] = os.getenv("SITENAME") or "short"


redis = redis.Redis(host="redis", port=6379)


@app.route("/", methods=["GET"])
def index():
    _ = [
        (f"{SERVER_URL}/{keys.decode()}", redis.get(keys).decode(), redis.get(keys + b"t").decode())
        for keys in redis.keys("[A-Z2-7]" * 7)
    ]
    return render_template("index.html", entries=_, error=session.get("error"))


@app.route("/", methods=["POST"])
def create_url():
    try:
        url = request.form.get("url")
        time = int(request.form.get("time"))
        check = True if request.form.get("check") == "on" else False

        if not validators.url(url):
            session["error"] = "url-not-valid"
            return redirect(url_for("index"))

        if time > TIMEOUT_MAX:
            session["error"] = "invalid-timeout"
            return redirect(url_for("index"))

        if check and vt_url_malicious(url):
            session["error"] = "malicious-url-detect"
            return redirect(url_for("index"))

        while True:
            new_r = b32encode(os.urandom(4)).decode()[:-1]
            if redis.get(new_r) == None:
                redis.setex(new_r, time, url)
                redis.setex(
                    new_r + "t",
                    time,
                    (datetime.now() + timedelta(seconds=time)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                )
                break

        session["error"] = ""
        return redirect(url_for("index"))
    except Exception as e:
        session["error"] = str(e)
        return redirect(url_for("index"))


@app.route("/<r>", methods=["GET"])
def go(r):
    url = redis.get(r[:7])

    if url:
        return redirect(url)
    else:
        session["error"] = "no-data"
        return redirect(url_for("index"))
