//////////////////
// Dependencies //
//////////////////
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <ctime>

using namespace std;

const bool debug = false;
const bool testing = false;



/////////////////
/// VARIABLES ///
/////////////////

// CONSTANT VARIABLES
const string honeyversion = "0.1";
const int heartbeattime = 10;

// SYSTEM VARIABLES
bool checkforupdates = true;
int startupchecks = 0;
int encounterederrors = 0;
bool attacked = false;
bool systemup = false;
int heartbeat = 29;
string erroroccurred = "";
int packetsreceivedSSH = 0;
int packetsreceivedAPI = 0;

bool serverdumpfilefound = false;

// DOCKER VARIABLES
int timesincelastcheckinSSH = 0;
long int lastcheckinSSH = 0;


// REPORT VARIABLES - SSH
bool SSHDockerActive = false;
bool generatingreportSSH = false;
string pubipSSH = "0.0.0.0";
int portSSH = 0;

// NETWORK VARIABLES
const int serverport1 = 80;
const int serverport2 = 11829;
const int BUFFER_SIZE = 1024;
int serverSocket1 = 0;
int serverSocket2 = 0;
int server_fd, new_socket;
int port1;
int server_fd2, new_socket2;
bool packetactive = false;

// FILES 
fstream iplist;             // IP BLOCKLIST TABLE
fstream maclist;            // MAC ADDRESSES FOR HONEYPIS
fstream severitylist;       // SEVERITY LIST OF OP ATTACKS
fstream acpmac;             // JSON LIST OF ACCOUNTS/MAC/API/ETC.
fstream blockedipstream;    // SERVER IP BLOCKLIST
fstream config1;            // serverconfig1
fstream logfile[256];       // Crashlogs
fstream passstream;         // USERNAME/PASSWORD JSON STREAM
fstream serverdump;         // SERVER DUMP FILE
fstream serverlogfile;            // SERVER LOG FILE

// TIME VARIABLES
long long int startuptime = 0;
long long int currenttime = 0;
long long int timesincestartup = 0;
int currenthour = 0;
int currentminute = 0;
int currentsecond = 0;
int currentdayofyear = 0;
int currentdays = 0;
int currentyear = 0;
int currentmonth = 0;
int secondsperyear = 31536000;
int daysperyear = 365.25;
int secondsperday = 86400;
int secondsperhour = 3600;
int secondsperminute = 60;
int minutesperhour = 60;
int hoursperday = 24;


long long int timers[10] = {};
bool calculatingtime = false;
// 0 - RESTART SSH DOCKER VARIABLE
// 1 - TIMER TO STOP BUFFER OVERFLOW ON SSH (80) DOCKER AND CAUSE CPU CRASH
// 2 - TIMER TO STOP BUFFER OVERFLOW ON ROUTER API (11829) PORT




int timedetector() {
    if (calculatingtime == true) {
        std::cout << "[WARNING] - Call to Time Calculation Called While Already Processing!" << std::endl;
        return 1;

    }  else {
        // TIME
        currenttime = time(NULL);

        // CURRENT SECONDS
        timesincestartup = currenttime - startuptime;
        currentsecond = currenttime % secondsperminute;

        // CURRENT MINUTES
        currentminute = currenttime - currentsecond;
        currentminute = currentminute % 3600;
        currentminute = currentminute / 60;

        // CURRENT HOURS
        currenthour = currenttime - ((currentminute * 60) + currentsecond);
        currenthour = currenthour % hoursperday;
        
        // CURRENT DAYS
        currentdays = currenttime - ((currenthour * 3600) + (currentminute * 60) + currentsecond);
        currentdays = currentdays / 86400;

        // CURRENT YEARS
        currentyear = 1970 + (currentdays / 365.25);

        // DEBUG PRINT VALUES TO CONSOLE
        if (debug == true) {
            std::cout << currentsecond << std::endl;
            std::cout << currentminute << std::endl;
            std::cout << currenthour << std::endl;
            std::cout << currentdays << std::endl;
            std::cout << currentyear << std::endl;
        }

        return 0;
    }

    return 1;
}






////////////////////////////
// Send to Logger Scripts //
////////////////////////////
void sendtolog(string data2) {
    std::cout << data2 << std::endl;
}
void sendtologopen(string data2) {
    std::cout << data2;
}
void sendtologclosed(string data2) {
    std::cout << data2 << std::endl;
}
void loginfo(string data2) {
    data2 = "[INFO] - " + data2;
    sendtolog(data2);
}
void logwarning(string data2) {
    data2 = "[WARNING] - " + data2;
    sendtolog(data2);
}
void logcritical(string data2) {
    data2 = "[CRITICAL] - " + data2;
    sendtolog(data2);
}





//////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (63599) //
//////////////////////////////////////////
void handleConnections(int server_fd) { 
    char buffer[1024] = {0};
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int new_socket;
    ssize_t valread;
    std::string hello = "Hello from server";

    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
        if (SSHDockerActive == false) {
            logcritical("SSH Docker Container Dead, Closing Port");
            return;
        }
        perror("accept");
        exit(EXIT_FAILURE);
    }

    timers[1] = time(NULL);

    while(SSHDockerActive == true) {
        read(new_socket, buffer, 1024);
        if (debug == true) {
            sendtologopen(buffer);
        }

        loginfo(buffer);

        if (buffer != NULL && attacked == false) {

            
            // HEARTBEAT COMMAND TO NOT SPAM LOG
            if (strcmp(buffer, "heartbeatSSH") == 0) {
                lastcheckinSSH = time(NULL);
                if (heartbeat >= 30) {
                    loginfo("Received heartbeat from SSH Guest VM");
                    heartbeat = 0;
                } else {
                    heartbeat = heartbeat + 1;
                }
                SSHDockerActive = true;
            }

            if(strcmp(buffer, "attacked") == 0) {
                logwarning("SSH attacked! - Logging...");
            }

        } else {
            if (buffer != NULL && attacked == true) {

                // ADD COMMANDS HERE OF BEING ATTACKED AND STORING THAT DATA

            } else {
                if (buffer == NULL) {
                    logcritical("INVALID CONNECTION RECEIVED, ignoring...");
                }
            }
        }

        // Send a hello message to the client
//        send(new_socket, hello.c_str(), hello.size(), 0);
//        std::cout << "Hello message sent" << std::endl;

        if (SSHDockerActive == false) {
            logcritical("No SSH Docker Container/Killing Thread");
        }

        // ANTI-CRASH PACKET FLOW CHECK
        if (timers[1] == time(NULL)) {
            packetsreceivedSSH = packetsreceivedSSH + 1;
            if (packetsreceivedSSH >= 10) {
                // KILL CONTAINER
                logcritical("PACKET OVERFLOW DETECTED ON SSH DOCKER PORT!/KILLING THREAD AND CONTAINER!");
                close(server_fd);
                timers[0] = time(NULL);
                SSHDockerActive = false;
    //            system(dockerkillguestssh);
                sleep(3);
      //          system(dockerremoveguestssh);
            }
        } else {
            timers[1] = time(NULL);
            packetsreceivedSSH = 0;
        }
    }
}





//////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (11535) //
//////////////////////////////////////////
void handle11535Connections(int server_fd2) {
    char buffer[1024] = {0};
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int new_socket2;
    ssize_t valread;
    std::string hello = "Hello from server";

    if ((new_socket2 = accept(server_fd2, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    } else {
        loginfo("11535 port initialized");
    }

    while(true) {
        read(new_socket2, buffer, 1024);
        sendtologopen(buffer);

        if (buffer != NULL && attacked == false) {

            // HEARTBEAT COMMAND TO NOT SPAM LOG
            if (strcmp(buffer, "heartbeatSSH")) {
                if (heartbeat >= 10) {
                    loginfo("Received heartbeat from SSH Guest VM");
                } else {
                    heartbeat = heartbeat + 1;
                }
            } 

        } else {
            if (buffer != NULL && attacked == true) {

            } else {
                if (buffer == NULL) {
                    logcritical("INVALID CONNECTION RECEIVED, ignoring...");
                }
            }
        }


        // ANTI-CRASH PACKET FLOW CHECK
        if (timers[2] == time(NULL)) {
            packetsreceivedAPI = packetsreceivedAPI + 1;
            if (packetsreceivedAPI >= 10) {
                // KILL CONTAINER
                logcritical("PACKET OVERFLOW DETECTED ON ROUTER API!");
                close(server_fd2);
            }
        } else {
            timers[2] = time(NULL);
            packetsreceivedAPI = 0;
        }



 //        Send a hello message to the client
         send(new_socket2, hello.c_str(), hello.size(), 0);
         std::cout << "Hello message sent" << std::endl;
    }
}



















int createnetworkport63599() {
    int PORT = 63599;
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    std::string hello = "Hello from server";
    int opt = 1;

    // SETUP NETWORK PORTS
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 63599
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}



/////////////////////////
// THE MAIN CRASH LOOP //
/////////////////////////





////////////////////////////
// THE MAIN SETUP SCRIPTS //
//////////////////////////// 
int setup() {
    sendtolog("Hello, World from 2515!");
    sendtolog("  _____     _____     ____________      _____      ____  ________________   ____         ____           ______________     ________________  ");
    sendtolog("  |   |     |   |    /            `     |   `      |  |  |               |  `  `        /   /           |             `   |               |  ");
    sendtolog("  |   |     |   |   /              `    |    `     |  |  |  |¯¯¯¯¯¯¯¯¯¯¯¯    `  `      /   /            |   |¯¯¯¯¯¯`   |  |_____    ______|  ");
    sendtolog("  |   |     |   |  /   /¯¯¯¯¯¯¯¯`   `   |     `    |  |  |  |____________     `  `    /   /             |   |______/   |        |   |        ");
    sendtolog("  |    ¯¯¯¯¯    |  |   |         |   |  |      `   |  |  |               |     `  `  /   /              |   __________/         |   |        ");
    sendtolog("  |    _____    |  |   |         |   |  |   |`  `  |  |  |               |      `  `/   /               |   |                   |   |        ");
    sendtolog("  |   |     |   |  |   |         |   |  |   | `  ` |  |  |  |¯¯¯¯¯¯¯¯¯¯¯¯        |     |                |   |                   |   |        ");
    sendtolog("  |   |     |   |  |   |         |   |  |   |  `  `|  |  |  |____________        |     |                |   |                   |   |        ");
    sendtolog("  |   |     |   |  `   `¯¯¯¯¯¯¯¯¯    /  |   |   `     |  |               |       |     |                |   |             |¯¯¯¯¯     ¯¯¯¯¯|  ");
    sendtolog("  |   |     |   |   `               /   |   |    `    |  |               |       |     |                |   |             |               |  ");
    sendtolog("  ¯¯¯¯¯     ¯¯¯¯¯    ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯    ¯¯¯¯      `¯¯¯   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯        ¯¯¯¯¯¯                 ¯¯¯¯¯             ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯   ");
    sendtolog("SERVER EDITION!");
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("Program by Matthew Whitworth (MawWebby)");
    sendtolog("Version: " + honeyversion);
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");

    // DELAY FOR SYSTEM TO START FURTHER (FIGURE OUT CURRENT TIME)
    sleep(1);

    startuptime = time(NULL);
    startupchecks = startupchecks + timedetector();


    // DETERMINE NETWORK CONNECTIVITY
    sendtologopen("[INFO] - Determining Network Connectivity...");
    int learnt = system("ping -c 5 8.8.8.8 > nul:");
    if (learnt == 0) {
        sendtologclosed("Done");
    } else {
        sendtologclosed("ERROR");
        logcritical("UNABLE TO DETERMINE NETWORK CONNECTIVITY!");
        logcritical("Killing");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }



    





    // CHECK FOR SYSTEM UPDATES
    sendtologopen("[INFO] - Checking for Updates...");
    if (checkforupdates == true) {
        // CHECK FOR SYSTEM UPDATES
        int returnedvalue = system("apt-get update > nul:");
        if (returnedvalue == 0) {
            sendtologclosed("Done");
        } else {
            sendtologclosed("ERROR");
            logcritical("UNABLE TO CHECK FOR SYSTEM UPDATES!");
            logcritical("This could be potentially dangerous!");
            logcritical("KILLING PROCESS!");
            startupchecks = startupchecks + 1;
            return 1;
            return 1;
            return 1;
        }



        // CHECK FOR SYSTEM UPDATES
        sendtologopen("[INFO] - Updating System...");
        int returnedvalue2 = system("apt-get upgrade -y > nul:");
        if (returnedvalue2 == 0) {
            sendtologclosed("Done");
        } else {
            sendtologclosed("ERROR");
            logcritical("UNABLE TO UPGRADE SYSTEM!");
            logcritical("This could be potentially dangerous!");
            logcritical("KILLING PROCESS!");
            startupchecks = startupchecks + 1;
            return 1;
            return 1;
            return 1;
        }

    } else {
        sendtologclosed("disabled");
        logwarning("UNABLE TO CHECK FOR UPDATES! (SYSTEM DISABLED)");
    }


    


    // OPEN SERVER FILES
    sendtologopen("[INFO] - Open IP LIST File...");

    int statuses = system("ls");
    iplist.open("/home/listfiles/iplist.json");
    maclist.open("home/listfiles/maclist.json");
    severitylist.open("/home/listfiles/severitylist.json");
    acpmac.open("/home/listfiles/acpmac.json");
    blockedipstream.open("/home/listfiles/ipsafety.txt");
    config1.open("/home/listfiles/serverconfig1.txt");
    // NO SETUP FOR LOGFILE
    passstream.open("/home/listfiles/passstream.json");
    serverdump.open("/home/serverdump/serverdump.txt");
    serverlogfile.open("/home/serverdump/log.txt");



    // VERIFY SERVER FILES ARE OPEN
    int testing = system("cd /home/crashlogs");
    if (testing != 0) {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN CRASHLOGS FOLDER!");
        startupchecks = startupchecks + 1;
    } else {
        int working = system("rm *");
        if (working != 0) {
            sendtolog("ERROR");
            logcritical("UNABLE TO CLEAR CRASHLOGS FOLDER!");
            startupchecks = startupchecks + 1;
        }
    }



    if (iplist.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN IP LIST FILE");
    } else {
        sendtolog("Done");
    }


    // ADD THE REST OF THE CHECKS AND MAKE SURE THAT THEY WORK HERE!




    // SEARCH FOR SERVER DUMP FILE
    if (serverdump.is_open() == true) {
        logwarning("SERVER DUMP FILE FOUND, ATTEMPTING TO RECOVER");
        serverdumpfilefound = true;
    } else {
        loginfo("No Server Dump File Found, Starting as BLANK SERVER");
        serverdumpfilefound = false;
    }
    









    int PORT = 63599;

    // OPEN NETWORK SERVER PORTS (1/3)
    sendtologopen("[INFO] - Opening Server Ports (1/3)");

    port1 = createnetworkport63599();

    sendtologclosed("Done");
    sleep(2);




    sleep(3);
    PORT = 11535;

    // OPEN NETWORK SERVER PORTS (2/3)
    sendtologopen("[INFO] - Opening Server Ports (2/3)...");

    int server_fd2, new_socket2;
    ssize_t valread2;
    struct sockaddr_in address2;
    socklen_t addrlen2 = sizeof(address2);
    int opt2 = 1;
    
    sleep(1);

    if((server_fd2 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 11535
    if (setsockopt(server_fd2, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt2, sizeof(opt2))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address2.sin_family = AF_INET;
    address2.sin_addr.s_addr = INADDR_ANY;
    address2.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd2, (struct sockaddr*)&address2, sizeof(address2)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd2, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    sendtologclosed("Done");
    sleep(2);





    // SERVER PORT LISTEN THREAD (2/3) (11535)
    sendtologopen("[INFO] - Creating server thread on port 11535 listen...");

    sleep(2);
    std::thread acceptingClientsThread2(handle11535Connections, server_fd2);
    acceptingClientsThread2.detach();
    sleep(1);

    sendtologclosed("Done");




    // SYSTEM STARTED
    sendtologopen("[INFO] - Updating API Token...");


    // FUTURE NETWORK COMMUNICATION TO UPDATE API TOKENS

    sendtolog("future");



    if (serverdumpfilefound == true) {
        loginfo("FUTURE THINGS!");
    }

    
    
    return 0;
}






int main() {

    // SETUP LOOP
    setup();

    // SERVER PORT LISTEN THREAD
    sendtologopen("[INFO] - Creating server thread on port 63599 listen...");

    sleep(2);
    std::thread acceptingClientsThread(handleConnections, port1);
    acceptingClientsThread.detach();
    sleep(1);

    sendtologclosed("Done");

    // STARTUP CHECKS
    if (startupchecks != 0) {
        logcritical("STARTUP CHECKS RETURNED EXIT CODE 1");
        logcritical("THE SYSTEM COULD NOT CONTINUE!");
        logcritical("ALL DOCKER CONTAINERS WILL BE STOPPED");

        // ADD FUTURE DOCKER CONTAINER INFORMATION
        close(serverport1);
        close(serverport2);
        sleep(10);
        int completion = system("docker kill * > nul:");
        sleep(10);

        // EXIT AND STOP PROCESSES
        return(1);
        return(1);
        return(1);
    }

    

    if (testing == true) {
        sendtologopen("[INFO] - Beta Testing Active...");
        sleep(1);
        sendtologclosed("Nothing to Test");
    } else {
        sendtolog("[INFO] - Not beta testing/Removing beta file...");
        startupchecks = startupchecks + system("rm test");
    }

    loginfo("Main HoneyPi has started successfully");

    // NETWORK INFORMATION
    char buffer[BUFFER_SIZE];
    sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // MAIN RUNNING LOOP
    while(true && startupchecks == 0 && encounterederrors == 0) {

        if (attacked == false) {
            sleep(2);
        } else {
            sleep(0.25);
            logwarning("Guest VM has been attacked, reporting...");
        }


        // WATCHDOG IN MAIN LOOP
        int differenceintimeSSH = time(NULL) - lastcheckinSSH;
        if (SSHDockerActive == true) {
            if (differenceintimeSSH >= 30) {
                logwarning("30 seconds since last SSH Heartbeat received");
            }

            if (differenceintimeSSH >= 45) {
                logcritical("45 seconds since last SSH Heartbeat received, assuming dead");
                close(server_fd);
                SSHDockerActive = false;
    //            system(dockerkillguestssh);
                sleep(3);
    //            system(dockerremoveguestssh);
                timers[0] = time(NULL);
            }
        } else {
            if (timers[0] != 0) {
                long long int changeintime = time(NULL) - timers[0];

                if (changeintime >= 60) {
                    logwarning("Attempting to restart SSH VM");
      //              system(dockerkillguestssh);
                    sleep(3);
        //            system(dockerremoveguestssh);
                    sleep(3);
          //          system(dockerstartguestssh);
                    SSHDockerActive = true;
                    lastcheckinSSH = time(NULL) + 10;
                    port1 = createnetworkport63599();
                    sleep(2);
                    std::thread acceptingClientsThread(handleConnections, port1);
                    acceptingClientsThread.detach();
                }
            } else {
                logwarning("Attempting to restart in 60 seconds!");
                timers[0] = time(NULL);
            }
        }

    }

    // ENCOUNTERED ERRORS
    if (encounterederrors != 0) {
        logcritical("HONEYPI-SERVER HAS ENCOUNTERED UNRECOVERABLE ERRORS WHILE RUNNING!");
        logcritical("HONEYPI-SERVER WILL NOW ATTEMPT A LOG DUMP!");
        


        logcritical("HONEYPI-SERVER WILL NOW ATTEMPT A SAVEFILE DUMP!");

        logcritical("ATTEMPTING TO END SERVER!!!");
        close(serverport1);
        close(serverport2);
    }
}