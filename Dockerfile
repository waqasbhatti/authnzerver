FROM python:3.8-slim-buster

RUN useradd -m -s /bin/bash authnzerver

WORKDIR /home/authnzerver
USER authnzerver

COPY --chown=authnzerver:authnzerver . .
RUN python3 -m venv /home/authnzerver/.env && . /home/authnzerver/.env/bin/activate && pip install --no-cache-dir pip setuptools wheel -U && pip install -r requirements.txt
RUN . /home/authnzerver/.env/bin/activate && pip install -e /home/authnzerver


EXPOSE 13141

ENTRYPOINT ["/home/authnzerver/docker_entrypoint.sh"]
