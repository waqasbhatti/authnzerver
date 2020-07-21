FROM python:3.8-slim-buster

RUN apt-get update \
  && apt-get --no-install-recommends -y install curl \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && useradd -m -s /bin/bash authnzerver

WORKDIR /home/authnzerver
USER authnzerver

COPY --chown=authnzerver:authnzerver . .
RUN python3 -m venv /home/authnzerver/.env \
  && . /home/authnzerver/.env/bin/activate \
  && pip install --no-cache-dir pip setuptools wheel -U \
  && pip install --no-cache-dir -r requirements.txt
RUN . /home/authnzerver/.env/bin/activate \
  && pip --no-cache-dir install -e /home/authnzerver \
  && mkdir basedir && chown -R authnzerver:authnzerver basedir
VOLUME ["/home/authnzerver/basedir"]

# define the health-check
HEALTHCHECK --interval=30s --timeout=5s CMD curl --silent --fail http://localhost:13431/health || exit 1

EXPOSE 13431
ENTRYPOINT ["/home/authnzerver/docker_entrypoint.sh"]
