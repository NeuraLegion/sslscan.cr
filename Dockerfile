FROM ubuntu:focal AS builder

LABEL authors="Bar Hofesh <Bar.Hofesh@neuralegion.com>, \
  Anatol Karalkou <anatol.karalkou@neuralegion.com>"

# Install Dependencies
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq --fix-missing
RUN apt-get install -y --no-install-recommends apt-utils ca-certificates curl \ 
  gnupg libdbus-1-dev build-essential libevent-dev libssl-dev libyaml-dev \
  libgmp-dev git libxml2 libxml2-dev libxslt1-dev build-essential patch \
  zlib1g-dev liblzma-dev openssh-server

# Setup for multiparse ssh
#RUN mkdir -p /root/.ssh
#COPY multiparse-cerebrum.private /root/.ssh/id_rsa
#RUN chmod 600 /root/.ssh/id_rsa
#RUN eval "$(ssh-agent)" && \
#    ssh-add /root/.ssh/id_rsa && \
#    ssh-keyscan -H github.com >> /etc/ssh/ssh_known_hosts

#SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://keybase.io/crystal/pgp_keys.asc | apt-key add -
RUN echo "deb https://dist.crystal-lang.org/apt crystal main" | tee \
  /etc/apt/sources.list.d/crystal.list
RUN apt-get update -qq
RUN apt-get install -y --no-install-recommends crystal

# Create relevant directories
RUN mkdir -p /opt/sslscan

WORKDIR /opt/sslscan

# Build NexPloit
COPY ./shard.yml /opt/sslscan/shard.yml
RUN shards update

COPY src /opt/sslscan/src
COPY spec /opt/sslscan/spec

RUN shards build --release

FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq --fix-missing && apt-get install \
  -y --no-install-recommends openssl libssl1.1 libdbus-1-3 libxml2 \
  libxml2-dev libevent-2.1 apt-utils ca-certificates libyaml-0-2 libxslt1-dev \
  build-essential zlib1g-dev liblzma-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/sslscan/bin/ameba /usr/bin/ameba

ENTRYPOINT ["/bin/sh", "-c", "/usr/bin/ameba"]
EXPOSE 80
