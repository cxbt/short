import os
import redis
import validators
from base64 import b32encode
from datetime import datetime, timedelta
from flask import Flask, redirect, render_template, request, session, url_for

from util import vt_url_malicious

TIMEOUT_MAX = 3600


app = Flask(__name__)
app.secret_key = os.urandom(16)

redis = redis.Redis(host="redis", port=6379)


@app.route("/", methods=["GET"])
def index():
    _ = [
        (keys, redis.get(keys), redis.get(keys + b"t"))
        for keys in redis.keys("[A-Z2-7]" * 7)
    ]
    return render_template("index.html", entries=_, error=session.get("error"))


@app.route("/create", methods=["POST"])
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


@app.route("/g/<r>", methods=["GET"])
def go(r):
    more = True if r[-1] == "+" else False
    r = r[:7] if more else r
    url = redis.get(r)

    if url:
        if more:
            time = redis.get(r + "t")
            return render_template(
                "more.html", entry=(request.url_root + "g/" + r, url, time)
            )
        else:
            return redirect(url)
    else:
        session["messages"] = "no-data"
        return redirect(url_for("index"))
