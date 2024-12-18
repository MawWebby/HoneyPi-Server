# From Base Image
FROM debian:bookworm-slim

# INSTALL NEEDED PACKAGES (DISABLE FOR SPEED BUILDING)
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y iputils-ping bash
RUN apt-get install -y g++
RUN apt-get install -y sudo
RUN apt-get install -y wget
RUN apt-get install -y apt-utils
RUN apt-get install -y openssl libssh-dev
RUN apt-get install -y mariadb-server
RUN apt-get install -y libcurl4
RUN apt-get install -y libcurl4-openssl-dev

# DEBUG UTILITIES
#RUN apt-get install -y gdbserver
#RUN apt-get install -y gdb g++
#EXPOSE 3000

# Expose Needed Ports
EXPOSE 80       
EXPOSE 443
EXPOSE 11829
EXPOSE 11830
EXPOSE 22221

# GENERATE OPENSSL KEYS
RUN mkdir /certs
RUN openssl genpkey -algorithm RSA -out /certs/private.key
RUN openssl req -x509 -key /certs/private.key -out /certs/server.crt -days 365 -subj "/C=US/ST=Missouri/L=Springfield/O=HoneyPi/OU=IT/CN=honeypi.basellinux.net/emailAddress=mawhitworth01@gmail.com"

# MKDIR FOR CONFIG FILES
RUN mkdir /home/listfiles

# MKDIR FOR CRASH LOGS
RUN mkdir /home/crashlogs

# MKDIR FOR SERVER SAVE/LOG DUMP
RUN mkdir /home/savedump

# MKDIR FOR HTML MAIN WEBPAGE
RUN mkdir /home/htmlmainweb

# MKDIR FOR ARCHIVE FILES
RUN mkdir /home/archives

# INSTALL MARIADB AND MARIADB CONNECTORS
RUN wget https://dlm.mariadb.com/3848191/Connectors/cpp/connector-cpp-1.1.4/mariadb-connector-cpp_1.1.4-1+maria~bookworm_arm64.deb
RUN dpkg -i mariadb-connector-cpp_1.1.4-1+maria~bookworm_arm64.deb

# Set Working Directory
COPY . /usr/src/honeypi
WORKDIR /usr/src/honeypi

##################
# STANDARD CODE: #
##################
RUN g++ -o run home.cpp \
adminconsole.cpp \
standardloops.cpp \
mariadbfunctions.cpp \
servermaintenance.cpp \
network.cpp \ 
backup.cpp \
encryption.cpp \
-lmariadbcpp -lssl -lcrypto -lcurl


ENTRYPOINT ["/bin/bash"]
#CMD ["/bin/bash"]

####################
# DEBUG ENTRYPOINT #
####################
#RUN g++ -o test servertest.cpp -lmariadbcpp -lssl -lcrypto -lcurl
#ENTRYPOINT ["./test"]
#ENTRYPOINT ["gdbserver", "localhost:3000", "/usr/src/honeypi/run"]
#RUN g++ -std=c++11 -o test test.cpp
#CMD ["/usr/src/test"]

############################
# REMOVE UNNEEDED PACKAGES #
############################
# SPEED BUILDING!!!
#RUN apt-get remove -y openssh-server 
#RUN apt-get remove -y g++ 
#RUN apt-get remove -y wget
#RUN apt-get remove -y apt-utils
#RUN apt-get autoremove -y

# CHANGE THE DEFAULT PIPE
RUN mv /bin/bash /bin/bash2 && ln -s /usr/src/honeypi/run /bin/bash

# REMOVE C++ SCRIPTS
RUN rm home.cpp
#RUN rm servertest.cpp

# Versions and Labels
LABEL Name=honeypiserver Versions=0.2
