# From Base Image
FROM debian:bookworm-slim

# INSTALL NEEDED PACKAGES (DISABLE FOR SPEED BUILDING)
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y iputils-ping bash 
RUN apt-get install -y g++
RUN apt-get install -y sudo zip unzip
RUN apt-get install -y wget
RUN apt-get install -y apt-utils
RUN apt-get install -y openssl libssh-dev
RUN apt-get install -y mariadb-server
RUN apt-get install -y libcurl4
RUN apt-get install -y libcurl4-openssl-dev
RUN apt-get install -y docker.io
RUN apt-get install -y cmake make
RUN mkdir /home/buildcache
WORKDIR /home/buildcache
RUN git clone https://github.com/trusch/libbcrypt
RUN mkdir /home/buildcache/libbcrypt/build
WORKDIR /home/buildcache/libbcrypt/build
RUN cmake ..
RUN make
RUN sudo make install
RUN sudo ldconfig
RUN cd /home/buildcache && rm -r *
RUN rm -r /home/buildcache

# Expose Needed Ports
EXPOSE 80       
EXPOSE 443
EXPOSE 11829

# GENERATE OPENSSL KEYS
RUN mkdir /certs
RUN openssl genpkey -algorithm RSA -out /certs/private.key
RUN openssl req -x509 -key /certs/private.key -out /certs/server.crt -days 365 -subj "/C=US/ST=Missouri/L=Springfield/O=HoneyPi/OU=IT/CN=honeypi.basellinux.net/emailAddress=mawhitworth01@gmail.com"

# MKDIR FOR CONFIG FILES
RUN mkdir /home/listfiles

# MKDIR FOR CRASH LOGS
RUN mkdir /home/crashlogs

# MKDIR FOR SERVER SAVE/LOG DUMP
RUN mkdir /home/serverdump

# MKDIR FOR HTML MAIN WEBPAGE
RUN mkdir /home/htmlmainweb

# MKDIR FOR ARCHIVE FILES
RUN mkdir /home/archives

# MKDIR FOR BACKUP FILES
RUN mkdir /home/backups

# MKDIRS FOR CRASHLOGS FOLDER
RUN mkdir /home/crashlogs/encrypted
RUN mkdir /home/crashlogs/finished

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
Databases/encryption.cpp \
handleapi.cpp \
handlehttps.cpp \
process.cpp \
Databases/jsonfunctions.cpp \
-lmariadbcpp -lssl -lcrypto -lcurl -lbcrypt


ENTRYPOINT ["/bin/bash"]


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

# Create the DB Tables
RUN mkdir /home/databases
RUN mv /usr/src/honeypi/Databases/command_severity.txt /home/databases/command_severity.txt
RUN mv /usr/src/honeypi/Databases/file_access_severity.txt /home/databases/file_access_severity.txt
RUN mv /usr/src/honeypi/Databases/file_changes_severity.txt /home/databases/file_changes_severity.txt
RUN mv /usr/src/honeypi/Databases/file_edit_severity.txt /home/databases/file_edit_severity.txt

# Remove All Build Files
RUN mv /usr/src/honeypi/run /usr/src/run
RUN mv /usr/src/honeypi/testreport.txt /home/testreport.txt
RUN rm -r /usr/src/honeypi* 
RUN mv /usr/src/run /usr/src/honeypi
RUN chmod 777 /home/testreport.txt

# Versions and Labels
LABEL Name=honeypiserver Versions=0.5
