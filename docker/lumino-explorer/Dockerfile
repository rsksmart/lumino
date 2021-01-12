FROM debian:stretch-slim

# Defining default Java and Maven version
ARG JAVA_VERSION="8.0.275-zulu"
ARG MAVEN_VERSION="3.6.2"

ENV HOME=/root

# Installing basic packages
RUN apt-get update && \
	apt-get install -y zip unzip curl supervisor systemd wget curl software-properties-common unzip zip ssh git && \
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
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && mvn --version"
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && mvn clean compile -f $HOME/lumino-explorer/lumino-explorer-api/pom.xml"

# Supervisod CONF
COPY assets/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 8080

# Define default command.
CMD ["/usr/bin/supervisord"]