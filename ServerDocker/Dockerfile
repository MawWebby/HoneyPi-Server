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

# Expose Needed Ports
EXPOSE 80
EXPOSE 11829
EXPOSE 11830

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
RUN apt-get install -y mariadb-server
RUN wget https://dlm.mariadb.com/3848191/Connectors/cpp/connector-cpp-1.1.4/mariadb-connector-cpp_1.1.4-1+maria~bookworm_arm64.deb
RUN dpkg -i mariadb-connector-cpp_1.1.4-1+maria~bookworm_arm64.deb


# Set Working Directory
COPY . /usr/src/honeypi
WORKDIR /usr/src/honeypi

# This command compiles your app using GCC, adjust for your source code
RUN g++ -o run home.cpp -lmariadbcpp
RUN g++ -o test servertest.cpp

# REMOVE UNNEEDED PACKAGES
# SPEED BUILDING!!!
#RUN apt-get remove -y openssh-server 
#RUN apt-get remove -y g++ 
#RUN apt-get remove -y wget
#RUN apt-get remove -y apt-utils
#RUN apt-get autoremove -y

# REMOVE C++ SCRIPTS
RUN rm home.cpp
RUN rm servertest.cpp

# This command runs your application, comment out this line to compile only
ENTRYPOINT ["./run"]
#CMD ["./usr/src/honeypi/run"]

# Versions and Labels
LABEL Name=honeypotpi-SERVER Versions=0.1
