# From Base Image
FROM debian:bookworm-slim

# INSTALL NEEDED PACKAGES (DISABLE FOR SPEED BUILDING)
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y iputils-ping bash
RUN apt-get install -y g++

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

# Set Working Directory
COPY . /usr/src/honeypi
WORKDIR /usr/src/honeypi

# This command compiles your app using GCC, adjust for your source code
RUN g++ -o run home.cpp
RUN g++ -o test servertest.cpp

# REMOVE UNNEEDED PACKAGES
RUN apt-get remove openssh-server -y
RUN apt-get remove g++ -y
RUN apt-get autoremove -y

# REMOVE C++ SCRIPTS
RUN rm home.cpp
RUN rm servertest.cpp

# This command runs your application, comment out this line to compile only
ENTRYPOINT ["./run"]
#CMD ["./usr/src/honeypi/run"]

# Versions and Labels
LABEL Name=honeypotpi-SERVER Versions=0.1
