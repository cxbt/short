import os
import redis
import validators
from base64 import b32encode
from datetime import datetime
from flask import Flask, redirect, render_template, session, request

from util import vt_url_malicious

TIMEOUT_MAX = 3600


app = Flask(__name__)
app.secret_key = os.urandom(16)

redis = redis.Redis(host="redis", port=6379)
# redis = redis.Redis(host="localhost", port=6379)


@app.route("/", methods=["GET"])
def index():
    short = [(keys, redis.get(keys)) for keys in redis.keys("[A-Z2-7]" * 7)]
    print(short)
    return render_template("index.html", entries=short)


@app.route("/create", methods=["POST"])
def create_url():
    try:
        url = request.form.get("url")
        time = int(request.form.get("time"))
        check = True if request.form.get("check") == "on" else False

        if not validators.url(url):
            session["messages"] = "url-not-valid"
            return redirect("/error")

        if time > TIMEOUT_MAX:
            session["messages"] = "invalid-timeout"
            return redirect("/error")

        if check and vt_url_malicious(url):
            session["messages"] = "malicious-url-detect"
            return redirect("/error")

        while True:
            new_r = b32encode(os.urandom(4)).decode()[:-1]
            if redis.get(new_r) == None:
                redis.setex(new_r, time, url)
                redis.setex(
                    new_r + "t", time, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                break

        return redirect("/")
    except Exception as e:
        session["messages"] = str(e)
        return redirect("/error")


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
        return redirect("/error")


@app.route("/error", methods=["GET"])
def error():
    return render_template("error.html", msg=session["messages"])


# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port="5000")
