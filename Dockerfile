FROM python:3.10

LABEL maintainer="Zella Zhong <zella@mask.io>"

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

RUN mkdir -p /app/log
RUN mkdir -p /app/data

COPY src .
COPY run.sh .
COPY supervisord.conf .

COPY .env.example .env

EXPOSE 5000
ENTRYPOINT ["./run.sh"]