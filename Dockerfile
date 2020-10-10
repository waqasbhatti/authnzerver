#
# stage 1: build psycopg2 for Postgres interface
#
FROM python:3.8-slim-buster as builder

ENV PSYCOPG2_VERSION 2.8.6

RUN apt-get update \
  && apt-get --no-install-recommends -y install libpq-dev gcc libc6-dev \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && pip wheel psycopg2==${PSYCOPG2_VERSION}

#
# stage 2: copy over built psycopg2 from previous container
#
FROM python:3.8-slim-buster

RUN apt-get update \
  && apt-get --no-install-recommends -y install curl libpq5 \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && useradd -m -s /bin/bash authnzerver

COPY --chown=authnzerver:authnzerver \
  --from=builder /psycopg2-2.8.6-cp38-cp38-linux_x86_64.whl /home/authnzerver

# use Tini for self-contained init daemon -- enables subprocess cleanup in K8s
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
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir \
       /home/authnzerver/psycopg2-2.8.6-cp38-cp38-linux_x86_64.whl \
  && rm /home/authnzerver/psycopg2-2.8.6-cp38-cp38-linux_x86_64.whl \
  && pip install --no-cache-dir install PyMySQL==0.10.1

COPY --chown=authnzerver:authnzerver . .
RUN . /home/authnzerver/.env/bin/activate \
  && pip --no-cache-dir install -e /home/authnzerver \
  && mkdir basedir && chown -R authnzerver:authnzerver basedir

EXPOSE 13431

VOLUME ["/home/authnzerver/basedir"]

# run tini as user, using the subprocess reaper and child group reaper options
ENTRYPOINT ["/tini", "-s", "-g", "--", "/home/authnzerver/docker_entrypoint.sh"]
