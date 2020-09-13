FROM debian:buster
RUN apt update
RUN apt install sqlite3 procps python3 python3-venv vim python3-setuptools python3-wheel build-essential