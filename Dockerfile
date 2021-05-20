# use Tini for self-contained init daemon -- enables sub/child process cleanup
# https://github.com/krallin/tini
ARG tini_version=v0.19.0

# build psycopg2
ARG psycopg2_version=2.8.6

# get PyMySQL
ARG pymysql_version=1.0.2

#
# stage 1: build psycopg2 for Postgres interface
#
FROM python:3.9-slim-buster as builder

# these are required because Docker is weird
# https://github.com/moby/moby/issues/34129
ARG tini_version
ARG psycopg2_version
ARG pymysql_version

RUN apt-get update \
  && apt-get --no-install-recommends -y install libpq-dev gcc libc6-dev \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && pip wheel psycopg2==${psycopg2_version}

#
# stage 2: copy over built psycopg2 from previous container
#
FROM python:3.9-slim-buster

# these are required because Docker is weird
# https://github.com/moby/moby/issues/34129
ARG tini_version
ARG psycopg2_version
ARG pymysql_version

RUN apt-get update \
  && apt-get --no-install-recommends -y install curl libpq5 \
  && apt-get -y clean && rm -rf /var/lib/apt/lists/* \
  && useradd -m -s /bin/bash authnzerver

# copy over the built psycopg2 wheel from the builder
COPY --chown=authnzerver:authnzerver \
  --from=builder \
    /psycopg2-${psycopg2_version}-*-linux_*.whl /home/authnzerver

ADD https://github.com/krallin/tini/releases/download/${tini_version}/tini /tini
RUN chmod +x /tini

WORKDIR /home/authnzerver
USER authnzerver

COPY --chown=authnzerver:authnzerver requirements.txt requirements.txt
RUN python3 -m venv /home/authnzerver/.env \
  && . /home/authnzerver/.env/bin/activate \
  && pip install --no-cache-dir pip setuptools wheel -U \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir \
       /home/authnzerver/psycopg2-${psycopg2_version}-*-linux_*.whl \
  && rm /home/authnzerver/psycopg2-${psycopg2_version}-*-linux_*.whl \
  && pip install --no-cache-dir install PyMySQL==${pymysql_version}

COPY --chown=authnzerver:authnzerver . .
RUN . /home/authnzerver/.env/bin/activate \
  && pip --no-cache-dir install -e /home/authnzerver \
  && mkdir basedir && chown -R authnzerver:authnzerver basedir

EXPOSE 13431

VOLUME ["/home/authnzerver/basedir"]

# run tini as user, using the subprocess reaper and child-group reaper options
ENTRYPOINT ["/tini", "-s", "-g", "--", "/home/authnzerver/docker_entrypoint.sh"]
