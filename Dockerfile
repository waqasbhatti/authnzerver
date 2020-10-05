FROM python:3.8-slim-buster

RUN apt-get update \
  && apt-get --no-install-recommends -y install curl \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && useradd -m -s /bin/bash authnzerver

# use Tini for self-contained init daemon
# https://github.com/krallin/tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

WORKDIR /home/authnzerver
USER authnzerver

COPY --chown=authnzerver:authnzerver requirements.txt requirements.txt
RUN python3 -m venv /home/authnzerver/.env \
  && . /home/authnzerver/.env/bin/activate \
  && pip install --no-cache-dir pip setuptools wheel -U \
  && pip install --no-cache-dir -r requirements.txt

COPY --chown=authnzerver:authnzerver . .
RUN . /home/authnzerver/.env/bin/activate \
  && pip --no-cache-dir install -e /home/authnzerver \
  && mkdir basedir && chown -R authnzerver:authnzerver basedir

EXPOSE 13431

VOLUME ["/home/authnzerver/basedir"]
ENTRYPOINT ["/tini", "-s", "-g", "--", "/home/authnzerver/docker_entrypoint.sh"]
