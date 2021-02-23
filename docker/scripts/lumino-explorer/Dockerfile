FROM debian:stable

# Defining default Java and Maven version
ARG JAVA_VERSION="8.0.275-zulu"
ARG MAVEN_VERSION="3.6.3"
ARG CHAIN_NAME=regtest

ENV HOME=/root
ENV MONGO_LOCATION=$HOME/mongo/mongodb-linux-x86_64-debian10-4.4.3
ENV DEBIAN_FRONTEND=noninteractive
ENV CURRENT_BRANCH=develop
ENV EXPLORER_PORT=8080

# Installing basic packages
RUN apt-get update && \
	apt-get install -y zip unzip curl supervisor systemd wget curl lsof nano nginx \
	software-properties-common unzip zip ssh git libcurl4 openssl liblzma5 tar && \
	rm -rf /var/lib/apt/lists/* && \
	rm -rf /tmp/*

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
RUN /bin/bash -c "source /root/.nvm/nvm.sh && nvm install v14 && npm config set user 0 && npm config set unsafe-perm true"

RUN wget https://downloads.mongodb.com/compass/mongosh_0.6.1_amd64.deb
RUN dpkg -i mongosh_0.6.1_amd64.deb

# Downloading SDKMAN!
RUN curl -s "https://get.sdkman.io" | bash

# Installing Java and Maven, removing some unnecessary SDKMAN files
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && \
    yes | sdk install java $JAVA_VERSION && \
    yes | sdk install maven $MAVEN_VERSION && \
    rm -rf $HOME/.sdkman/archives/* && \
    rm -rf $HOME/.sdkman/tmp/*"

# Install Lumino Explorer.
RUN git clone https://github.com/rsksmart/lumino-explorer.git $HOME/lumino-explorer
RUN cd $HOME/lumino-explorer && git checkout $CURRENT_BRANCH
RUN /bin/bash -c "source /root/.nvm/nvm.sh && npm install --prefix $HOME/lumino-explorer/lumino-explorer-web"
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && mvn clean compile -f $HOME/lumino-explorer/lumino-explorer-api/pom.xml"

# Copy assets
COPY assets/${CHAIN_NAME}/application.properties $HOME/lumino-explorer/lumino-explorer-api/src/main/resources/application-prod.properties
COPY assets/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY assets/startExplorer /usr/local/bin
COPY assets/deleteDB.js /root/deleteDB.js
COPY assets/createDB.js /root/createDB.js
COPY assets/nginx.conf /etc/nginx/sites-enabled/default

RUN mkdir /var/www/html/explorer

RUN chmod +x /usr/local/bin/startExplorer

EXPOSE $EXPLORER_PORT

# Define default command.
CMD ["/usr/bin/supervisord"]
