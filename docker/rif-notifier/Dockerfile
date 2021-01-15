FROM debian:stable

# Defining default Java and Maven version
ARG JAVA_VERSION="8.0.275-zulu"
ARG MAVEN_VERSION="3.6.3"

ENV HOME=/root
ENV MONGO_LOCATION=$HOME/mongo/mongodb-linux-x86_64-debian10-4.4.3
ENV DEBIAN_FRONTEND=noninteractive
ENV CURRENT_BRANCH=master
ENV NOTIFIER_PORT=8080

# Installing basic packages
RUN apt-get update && \
	apt-get install -y zip unzip curl supervisor systemd wget curl lsof default-mysql-client \
	software-properties-common unzip zip ssh git libcurl4 openssl liblzma5 tar nano && \
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

# Install Rif Notifier
RUN git clone https://github.com/rsksmart/rif-notifier.git $HOME/rif-notifier
RUN cd $HOME/rif-notifier && git checkout $CURRENT_BRANCH
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && mvn clean compile -f $HOME/rif-notifier/pom.xml"

# Copy assets
COPY assets/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY assets/startNotifier /usr/local/bin

RUN chmod +x /usr/local/bin/startNotifier

EXPOSE $NOTIFIER_PORT

# Define default command.
CMD ["/usr/bin/supervisord"]