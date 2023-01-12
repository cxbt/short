FROM python:3

WORKDIR /usr/src/app

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV VT_APIKEY=3781b656df6a618bc05d9ec7b82895ce36cdffb462f8dc091341427ec473dcb6

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD [ "flask", "run" ]