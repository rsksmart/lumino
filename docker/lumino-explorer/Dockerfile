FROM debian:stable

# Defining default Java and Maven version
ARG JAVA_VERSION="8.0.275-zulu"
ARG MAVEN_VERSION="3.6.3"

ENV HOME=/root
ENV MONGO_LOCATION=$HOME/mongo/mongodb-linux-x86_64-debian10-4.4.3
ENV DEBIAN_FRONTEND=noninteractive
ENV CURRENT_BRANCH=develop

# Installing basic packages
RUN apt-get update && \
	apt-get install -y zip unzip curl supervisor systemd wget curl lsof \
	software-properties-common unzip zip ssh git libcurl4 openssl liblzma5 tar && \
	rm -rf /var/lib/apt/lists/* && \
	rm -rf /tmp/*

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
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && mvn clean compile -f $HOME/lumino-explorer/lumino-explorer-api/pom.xml"

# Installing Mongo DB
RUN mkdir $HOME/mongo
RUN wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian10-4.4.3.tgz -P $MONGO_LOCATION
RUN cd $HOME/mongo && tar -zxvf $MONGO_LOCATION/mongodb-linux-x86_64-debian10-4.4.3.tgz
RUN ln -s $MONGO_LOCATION/bin/* /usr/local/bin

# Copy assets
COPY assets/application.properties $HOME/lumino-explorer/lumino-explorer-api/src/main/resources/application-prod.properties
COPY assets/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY assets/startExplorer /usr/local/bin

RUN chmod +x /usr/local/bin/startExplorer

EXPOSE 8080

# Define default command.
CMD ["/usr/bin/supervisord"]