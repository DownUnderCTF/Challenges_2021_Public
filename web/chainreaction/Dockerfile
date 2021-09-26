FROM python:3.7

ENV INSTALL_PATH /app
RUN mkdir -p $INSTALL_PATH
RUN apt-get update && \
    apt-get install -y netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $INSTALL_PATH
RUN mkdir -p /app/chainreaction
COPY ./challenge/chainreaction /app/chainreaction
COPY ./challenge/ /app
RUN pip install -r requirements.txt
RUN chmod +x /app/wait-for-it.sh
CMD ["/bin/sh", "-c", "/app/wait-for-it.sh --strict -t 60 $MYSQL_HOST:3306 -- python3 /app/app.py"]