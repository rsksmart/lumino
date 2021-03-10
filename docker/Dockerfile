FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LUMINO_BRANCH=develop
ENV RIF_COMMS_BRANCH=grpc-api
ENV NODE_PORT=5001
ENV NETWORK_ID=33
ENV RSK_ENDPOINT="http://localhost:4444"

# Installing basic packages
RUN apt-get update && \
	apt-get install -y build-essential zip unzip curl supervisor systemd wget curl lsof nano nginx \
	software-properties-common unzip zip ssh git libcurl4 openssl liblzma5 tar
RUN apt-get install -y libsecp256k1-dev libssl-dev automake pkg-config libtool libffi-dev libgmp-dev libyaml-cpp-dev \
	libreadline-gplv2-dev libncursesw5-dev libssl-dev \
    libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev \
	rm -rf /var/lib/apt/lists/* && \
	rm -rf /tmp/*

RUN cd /usr/src && wget https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tgz \
    && tar xzf Python-3.7.9.tgz && cd Python-3.7.9 && ./configure --enable-optimizations && make altinstall

RUN python3.7 -V && python -V

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
RUN /bin/bash -c "source /root/.nvm/nvm.sh && nvm install v14.13 && npm config set user 0 && npm config set unsafe-perm true"

# Installing rif-comms Node
RUN git clone https://github.com/rsksmart/rif-communications-pubsub-bootnode -b $RIF_COMMS_BRANCH /root/rif-communications-pubsub-bootnode
RUN /bin/bash -c "source /root/.nvm/nvm.sh && nvm use 14.13 && cd /root/rif-communications-pubsub-bootnode && npm install"

# Installing Lumino Node
RUN git clone https://github.com/rsksmart/lumino.git -b $LUMINO_BRANCH /root/lumino
COPY assets/startLumino /root/lumino
COPY assets/createEnvironment /root/lumino
COPY assets/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /root/lumino/createEnvironment
RUN chmod +x /root/lumino/startLumino
RUN /bin/bash -c "source /root/.pyenv-setup && cd /root/lumino && ./createEnvironment"

EXPOSE $NODE_PORT

# Define default command.
CMD ["/usr/bin/supervisord"]
