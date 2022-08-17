# setup step
FROM debian:stable AS build
env DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y \
    build-essential \
    libffi-dev \
    libpython3-dev \
    python3-cffi \
    python3-dev \
    python3-venv \
    curl \
    git

COPY . /opt/sunet/sunet-auth-server/.
RUN cd /opt/sunet/sunet-auth-server/ && git show --summary > /revision.txt
RUN rm /opt/sunet/sunet-auth-server/.git -r
RUN /opt/sunet/sunet-auth-server/docker/setup_venv.sh

# actual image
FROM debian:stable
env DEBIAN_FRONTEND noninteractive
#
# Install dependencies and tools that are helpful when troubleshooting
#
RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y \
      bind9-host \
      curl \
      iputils-ping \
      net-tools \
      netcat-openbsd \
      procps \
      python3-minimal \
      python3-distutils \
      xmlsec1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN addgroup --system sunet && adduser --system --shell /bin/false sunet

RUN mkdir -p /var/log/sunet && chown sunet: /var/log/sunet && chmod 770 /var/log/sunet

COPY --from=build /revision.txt /revision.txt
COPY --from=build /opt/sunet/ /opt/sunet/

WORKDIR /opt/sunet

EXPOSE 8080

COPY docker/start-fastapi.sh /start-fastapi.sh

HEALTHCHECK --interval=27s CMD curl http://localhost:8080/status/healthy | grep -q STATUS_OK

ENTRYPOINT [ "/bin/bash"]

CMD [ "/start-fastapi.sh" ]
