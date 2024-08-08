# From Base Image
FROM debian:bookworm-slim

# INSTALL NEEDED PACKAGES (DISABLE FOR SPEED BUILDING)
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y iputils-ping bash
RUN apt-get install -y g++

# REMOVE UNNEEDED PACKAGES
RUN apt-get remove openssh-server -y

# Expose Needed Ports
EXPOSE 80
EXPOSE 11829

# MKDIR FOR CONFIG FILES
RUN mkdir /home/listfiles

# MKDIR FOR CRASH LOGS
RUN mkdir /home/crashlogs

# MKDIR FOR SERVER SAVE/LOG DUMP
RUN mkdir /home/savedump

# Set Working Directory
COPY . /usr/src/honeypi
WORKDIR /usr/src/honeypi

# This command compiles your app using GCC, adjust for your source code
RUN g++ -o run home.cpp

# This command runs your application, comment out this line to compile only
ENTRYPOINT ["./run"]

# Versions and Labels
LABEL Name=honeypotpi-SERVER Versions=0.1A
