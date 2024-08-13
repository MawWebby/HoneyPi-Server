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
#include <random>

const bool debug = false;
const bool testing = false;



/////////////////
/// VARIABLES ///
/////////////////

// CONSTANT VARIABLES
const std::string honeyversion = "0.1";
const int heartbeattime = 10;

// SYSTEM VARIABLES
bool checkforupdates = true;
int startupchecks = 0;
int encounterederrors = 0;
bool attacked = false;
bool systemup = false;
int heartbeat = 29;
std::string erroroccurred = "";
bool logfilepresent = false;


bool serverdumpfilefound = false;

// DOCKER VARIABLES
int timesincelastcheckinSSH = 0;
long int lastcheckinSSH = 0;



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
bool runningnetworksportAPI = true;

// FILES 
//std::fstream ipliststrict;         // IP BLOCKLIST TABLE (STRICT 90 DAY REMOVAL W/O EXCEPTIONS)
//std::fstream ipliststandard;       // IP BLOCKLIST TABLE (STANDARD 45 DAY REMOVAL W/ EXCEPTIONS)
//std::fstream iplistsmoreinfo;      // INFO ABOUT IP REPORTED/REPORTS/LATEST REPORT/EXPIRATION DATE
//std::fstream maclist;              // MAC ADDRESSES FOR HONEYPIS
//std::fstream severitylist;         // SEVERITY LIST OF OP ATTACKS
//std::fstream acpmac;               // JSON LIST OF ACCOUNTS/MAC/API/ETC.
//std::fstream blockedipstream;      // SERVER IP BLOCKLIST
//std::fstream config1;              // serverconfig1
std::fstream cogfile[256];         // Crashlogs
//std::fstream userstream;           // USERNAME JSON STREAM
//std::fstream passstream;           // PASSWORD JSON STREAM
//std::fstream serverdump;           // SERVER DUMP FILE
//std::fstream serverlogfile;        // SERVER LOG FILE

// FILE LOCATIONS
const char* ipliststrictfile = "/home/listfiles/ipliststrict.txt";
const char* ipliststandardfile = "/home/listfiles/ipliststandard.txt";
const char* iplistsmoreinfofile = "/home/listfiles/iplistsmoreinfo.txt";
const char* maclistfile = "/home/listfiles/maclist.txt";
const char* severitylistfile = "/home/listfiles/severitylist.txt";
const char* acpmacfile = "/home/listfiles/acpmac.txt";
const char* blokedipstreamfile = "/home/listfiles/ipsafety.txt";
const char* config1file = "/home/listfiles/serverconfig1.txt";
const char* userstreamfile = "/home/listfiles/userstream.txt";
const char* passstreamfile = "/home/lsitfiles/passstream.txt";
const char* serverdumpfile = "/home/serverdump/serverdump.txt";
const char* serverlogfilefile = "/home/serverdump/log.txt";
const char* foldersaccessedfile = "/home/listfiles/foldacc.txt";
const char* filesaccessedfile = "/home/listfiles/fileacc.txt";
const char* cmdrunfile = "/home/listfiles/cmdrun.txt";
const char* filearguments = "ios::in | ios::out";


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
// 0 - 




int timedetector() {
    if (calculatingtime == true) {
        std::cout << "[WARNING] - Call to Time Calculation Called While Already Processing!" << std::endl;
        return 1;

    }  else {
        calculatingtime = true;

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

        calculatingtime = false;
        return 0;
    }

    calculatingtime = false;
    return 1;
}






////////////////////////////
// Send to Logger Scripts //
////////////////////////////
void sendtolog(std::string data2) {
    std::cout << data2 << std::endl;
}
void sendtologopen(std::string data2) {
    std::cout << data2;
}
void sendtologclosed(std::string data2) {
    std::cout << data2 << std::endl;
}
void loginfo(std::string data2) {
    data2 = "[INFO] - " + data2;
    sendtolog(data2);
}
void logwarning(std::string data2) {
    data2 = "[WARNING] - " + data2;
    sendtolog(data2);
}
void logcritical(std::string data2) {
    data2 = "[CRITICAL] - " + data2;
    sendtolog(data2);
}



std::string generateRandomStringHoneyPI() {
    loginfo("CREATING NEW HoneyPi API KEY");

    // Define the list of possible characters
    const std::string CHARACTERS
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
          "wxyz0123456789";

    // Create a random number generator
    std::random_device rd;
    std::mt19937 generator(rd());

    // Create a distribution to uniformly select from all
    // characters
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    // Generate the random string
    std::string random_string = "PI";
    for (int i = 0; i < 62; ++i) {
        random_string += CHARACTERS[distribution(generator)];
    }

    loginfo(random_string);

    return random_string;
}


std::string generateRandomStringRouterAPI() {
    loginfo("CREATING NEW ROUTER API KEY");

    // Define the list of possible characters
    const std::string CHARACTERS
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
          "wxyz0123456789";

    // Create a random number generator
    std::random_device rd;
    std::mt19937 generator(rd());

    // Create a distribution to uniformly select from all
    // characters
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    // Generate the random string
    std::string random_string = "RO";
    for (int i = 0; i < 62; ++i) {
        random_string += CHARACTERS[distribution(generator)];
    }

    loginfo(random_string);

    return random_string;
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
        perror("accept");
        exit(EXIT_FAILURE);
    }

    timers[1] = time(NULL);

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


        // ANTI-CRASH PACKET FLOW CHECK



        // NEED EXPANDED FOR SERVER APPLICATION!!!


        /*
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
        */    

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


        // NEED EXPANDED FOR SERVER APPLICATION!!!


        /*
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
        */



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

    generateRandomStringHoneyPI();
    generateRandomStringRouterAPI();
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
    /*
    sendtologopen("[INFO] - Open IP LIST File...");
  //  std::ifstream ipliststrict;
  //  ipliststrict.open(ipliststrict);
  //  ipliststrict.open(ipliststrictfile);
    ipliststandard.open(ipliststandardfile);
  //  iplistsmoreinfo.open(iplistsmoreinfofile);
    maclist.open("/home/listfiles/maclist.txt",  std::ios::in | std::ios::out | std::ios::app);
    severitylist.open("/home/listfiles/severitylist.txt");
    acpmac.open("/home/listfiles/acpmac.txt");
    blockedipstream.open("/home/listfiles/ipsafety.txt", std::ios::in | std::ios::out | std::ios::app);
    config1.open("/home/listfiles/serverconfig1.txt");
    // NO SETUP FOR COGFILE
    userstream.open("/home/listfiles/userstream.txt");
    passstream.open("/home/listfiles/passstream.txt");
    serverdump.open("/home/serverdump/serverdump.txt");
    
    serverlogfile.open("/home/serverdump/log.txt");
    */



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

/*
    if (ipliststrict.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN STRICT IP LIST FILE");
    } else {
        sendtolog("Done");
    }
    */
/*
    if (ipliststandard.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN STANDARD IP LIST FILE");
    } else {
        sendtolog("Done");
    }


    if (iplistsmoreinfo.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN MORE INFO IP LIST FILE");
    } else {
        sendtolog("Done");
    }
    

    if (maclist.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN MAC LIST FILE");
    }

    if (severitylist.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN SEVERITY IP LIST FILE");
    } 

    if (acpmac.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN ACCOUNTS AND MACS FILE");
    }

    if (blockedipstream.is_open() != true) {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN BLOCKED IP STREAM FILE!");
        logcritical("STARTING WITHOUT NETWORK API PORT!");
    }

    if (config1.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN CONFIG1 FILE!");
    }

    if (userstream.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN USER STREAM FILE!");
    }

    if (passstream.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN PASS STREAM FILE!");
    }

    if (serverlogfile.is_open() != true) {
        startupchecks = startupchecks + 1;
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN SERVER LOG FILE!");
        logfilepresent = false;
    } else {
        logfilepresent = true;
    }

    sendtolog("Done");





    // SEARCH FOR SERVER DUMP FILE
    loginfo("Searching for Server Dump File");
    if (serverdump.is_open() == true) {
        logwarning("SERVER DUMP FILE FOUND, ATTEMPTING TO RECOVER");
        serverdumpfilefound = true;
    } else {
        loginfo("No Server Dump File Found, Starting as BLANK SERVER");
        serverdumpfilefound = false;
    }


    if (ipliststandard.fail()) {
        std::cerr << "Stream is in a failed state before writing." << std::endl;
        blockedipstream.clear();  // Clear error state
    }
    */



    // OPEN THE SERVER FILES NEW
    std::string versionID;
    std::string currentversionID = "Version: " + honeyversion + "\n";
    std::string compressed;
    int migration = 0;
    logcritical(currentversionID);





    // IPLIST STRICT
    sendtologopen("[INFO] - Attempting to Read from IP LIST Strict TXT File...");
    std::ifstream ipliststrict;
    ipliststrict.open(ipliststrictfile);
    if (ipliststrict.is_open() == true) {
        std::getline(ipliststrict, versionID);
        if (versionID != "") {
            if (versionID.substr(1,0) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }            
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - IP LIST STRICT - No Version Found, Writing New Version...");
            ipliststrict.close();
            std::ofstream ipliststrict;
            ipliststrict.open(ipliststrictfile);
            ipliststrict.seekp(0);
            ipliststrict << currentversionID << '\n';
            ipliststrict.flush();
            if (ipliststrict.fail() == true) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO IPLISTSTRICT");
                if (ipliststrict.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                ipliststrict.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different IP List Strict Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("No migration steps detected");
            } else {
                loginfo("IP LIST STRICT Started...");
            }
        }
    } else {
        sendtolog("ERROR!");
        logcritical("UNABLE TO OPEN IP LIST Strict TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    ipliststrict.close();
    


    // IP LIST STANDARD
    sendtologopen("[INFO] - Attempting to Read from IP List Standard File...");
    std::ifstream ipliststandard;
    ipliststandard.open(ipliststandardfile);
    if(ipliststandard.is_open() == true) {
        std::getline(ipliststandard, versionID);
        if (versionID != "") {
            if (versionID.substr(1,0) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - IP LIST STANDARD - No Version Found, Writing New Version...");
            ipliststandard.close();
            std::ofstream ipliststandard;
            ipliststandard.open(ipliststandardfile);
            ipliststandard.seekp(0);
            ipliststandard << currentversionID << '\n';
            ipliststandard.flush();
            if (ipliststandard.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO IPLISTSTANDARD");
                if (ipliststandard.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                ipliststandard.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different IP List Standard Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("IP LIST STANDARD Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN IP LIST Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    ipliststandard.close();

    

    // IP LIST MORE INFO
    sendtologopen("[INFO] - Attempting to Read from IP LIST MORE INFO TXT FILE");
    std::ifstream iplistsmoreinfo;
    iplistsmoreinfo.open(iplistsmoreinfofile);
    if (iplistsmoreinfo.is_open() == true) {
        std::getline(iplistsmoreinfo, versionID);
        if (versionID != "") {
            if (versionID.substr(1,0) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }            
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - IP LIST MORE INFO - No Version Found, Writing New Version...");
            iplistsmoreinfo.close();
            std::ofstream iplistsmoreinfo;
            iplistsmoreinfo.open(iplistsmoreinfofile);
            iplistsmoreinfo.seekp(0);
            iplistsmoreinfo << currentversionID << '\n';
            iplistsmoreinfo.flush();
            if (iplistsmoreinfo.fail() == true) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO IP LIST MORE INFO");
                if (iplistsmoreinfo.bad() == true) {
                    logcritical("I/O ERROR");
                }
                startupchecks = startupchecks + 1;
                iplistsmoreinfo.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different IP List Standard Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("IP LIST MORE INFO Started...");
            }
        }
    } else {
        sendtolog("ERROR!");
        logcritical("UNABLE TO OPEN IP LIST MORE INFO TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    iplistsmoreinfo.close();
    




    // MAC LIST INFO
    sendtologopen("[INFO] - Attempting to Read from MAC LIST TXT FILE...");
    std::ifstream maclist;
    maclist.open(maclistfile);
    if (maclist.is_open() == true) {
        std::getline(maclist, versionID);
        if (versionID != "") {
            if (versionID.substr(1,0) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }            
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - MAC LIST - No Version Found, Writing New Version...");
            maclist.close();
            std::ofstream maclist;
            maclist.open(maclistfile);
            maclist.seekp(0);
            maclist << currentversionID << '\n';
            maclist.flush();
            if (maclist.fail() == true) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO MAC LIST FILE");
                if (maclist.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                maclist.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different Mac List Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("No migration steps detected");
            } else {
                loginfo("MAC LIST Started...");
            }
        }
    } else {
        sendtolog("ERROR!");
        logcritical("UNABLE TO OPEN MAC LIST TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    maclist.close();
    

    // SEVERITY LIST INFO
    sendtologopen("[INFO] - Attempting to Read from Severity List TXT File...");
    std::ifstream severitylist;
    severitylist.open(severitylistfile);
    if (severitylist.is_open() == true) {
        std::getline(severitylist, versionID);
        if (versionID != "") {
            if (versionID.substr(1,0) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }            
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - SEVERITY LIST - No Version Found, Writing New Version...");
            severitylist.close();
            std::ofstream severitylist;
            severitylist.open(severitylist);
            severitylist.seekp(0);
            severitylist << currentversionID << '\n';
            severitylist.flush();
            if (severitylist.fail() == true) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO SEVERITYLIST");
                if (severitylist.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                severitylist.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different Severity List Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("No migration steps detected");
            } else {
                loginfo("SEVERITY LIST Started...");
            }
        }
    } else {
        sendtolog("ERROR!");
        logcritical("UNABLE TO OPEN IP LIST Strict TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    maclist.close();
    

    // Accounts/Macs/APIs INFO
    std::getline(acpmac, versionID);
    if (versionID != "") {
        compressed = versionID.substr(9,10);
    } else {
        compressed = "";
    }
    if (compressed == "") {
        logwarning("No Version Found, Installing New Version");
        acpmac << currentversionID << std::endl;
    } else {
        if (compressed != honeyversion) {
            migration = migration + 1;
            logwarning("Detected Different ACPMAC Version, Attempting to Update!");
            /*
            // MIGRATION STEPS
            if (float(compressed) > float(honeyversion)) {
                logcritical("Newer Version of File Detected than Server, Not Starting Server!");
                startupchecks = startupchecks + 1;
            }

            if (float(compressed) = 0.1) {
                loginfo("No Update Required");
            }
            */

        } else {
            loginfo("Detected Correct ACPMAC Version, Continuing");
        }
    }

    // SEVERITY LIST INFO
    std::getline(blockedipstream, versionID);
    if (versionID != "") {
        compressed = versionID.substr(9,10);
    } else {
        compressed = "";
    }
    if (compressed == "") {
        logwarning("No Version Found, Installing New Version");
        blockedipstream << currentversionID << std::endl;
    } else {
        if (compressed != honeyversion) {
            migration = migration + 1;
            logwarning("Detected Different IPSAFETY Version, Attempting to Update!");
            /*
            // MIGRATION STEPS
            if (float(compressed) > float(honeyversion)) {
                logcritical("Newer Version of File Detected than Server, Not Starting Server!");
                startupchecks = startupchecks + 1;
            }

            if (float(compressed) = 0.1) {
                loginfo("No Update Required");
            }
            */

        } else {
            loginfo("Detected Correct IPSAFETY Version, Continuing");
        }
    }

    // CONFIG1 INFO
    std::getline(config1, versionID);
    if (versionID != "") {
        compressed = versionID.substr(9,10);
    } else {
        compressed = "";
    }
    if (compressed == "") {
        logwarning("No Version Found, Installing New Version");
        config1 << currentversionID << std::endl;
    } else {
        if (compressed != honeyversion) {
            migration = migration + 1;
            logwarning("Detected Different Config1 Version, Attempting to Update!");
            /*
            // MIGRATION STEPS
            if (float(compressed) > float(honeyversion)) {
                logcritical("Newer Version of File Detected than Server, Not Starting Server!");
                startupchecks = startupchecks + 1;
            }

            if (float(compressed) = 0.1) {
                loginfo("No Update Required");
            }
            */

        } else {
            loginfo("Detected Correct Config1 Version, Continuing");
        }
    }

    // USERSTREAM INFO
    std::getline(userstream, versionID);
    if (versionID != "") {
        compressed = versionID.substr(9,10);
    } else {
        compressed = "";
    }
    if (compressed == "") {
        logwarning("No Version Found, Installing New Version");
        userstream << currentversionID << std::endl;
    } else {
        if (compressed != honeyversion) {
            migration = migration + 1;
            logwarning("Detected Different USERSTREAM Version, Attempting to Update!");
            /*
            // MIGRATION STEPS
            if (float(compressed) > float(honeyversion)) {
                logcritical("Newer Version of File Detected than Server, Not Starting Server!");
                startupchecks = startupchecks + 1;
            }

            if (float(compressed) = 0.1) {
                loginfo("No Update Required");
            }
            */

        } else {
            loginfo("Detected Correct USERSTREAM Version, Continuing");
        }
    }

    // PASSSTREAM INFO
    std::getline(passstream, versionID);
    if (versionID != "") {
        compressed = versionID.substr(9,10);
    } else {
        compressed = "";
    }
    if (compressed == "") {
        logwarning("No Version Found, Installing New Version");
        passstream << currentversionID << std::endl;
    } else {
        if (compressed != honeyversion) {
            migration = migration + 1;
            logwarning("Detected Different PASSSTREAM Version, Attempting to Update!");
            /*
            // MIGRATION STEPS
            if (float(compressed) > float(honeyversion)) {
                logcritical("Newer Version of File Detected than Server, Not Starting Server!");
                startupchecks = startupchecks + 1;
            }

            if (float(compressed) = 0.1) {
                loginfo("No Update Required");
            }
            */

        } else {
            loginfo("Detected Correct PASSSTREAM Version, Continuing");
        }
    }



    // CHECK BEFORE REST OF SERVER STARTUP IF FILES WERE NOT CONFIGURED CORRECTLY
    if (startupchecks != 0) {
        logcritical("STARTUP CHECKS DOES NOT EQUAL 0!");
        logcritical("STOPPING SERVER!");
        return 1;
        return 1;
        return 1;
    }



    // START NETWORK PORTS CONFIGURATION
    
    // OPEN NETWORK SERVER PORTS (1/3)
    int PORT = 63599;
    sendtologopen("[INFO] - Opening Server Ports (1/3)");
    port1 = createnetworkport63599();
    sendtologclosed("Done");
    sleep(2);
    sleep(3);

    // OPEN NETWORK SERVER PORTS (2/3)
    PORT = 11535;
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
    int startup = setup();

    if (startup != 0) {
        logcritical("STARTUP CHECKS RETURNED EXIT CODE 1");
        logcritical("THE SYSTEM COULD NOT CONTINUE!");
        logcritical("ALL DOCKER CONTAINERS WILL BE STOPPED");

        close(serverport1);
        close(serverport2);
        sleep(5);

        // EXIT AND STOP PROCESSES
        return(1);
        return(1);
        return(1);
    } else {


        // SERVER PORT LISTEN THREAD
        sendtologopen("[INFO] - Creating server thread on port 63599 listen...");

        sleep(2);
        std::thread acceptingClientsThread(handleConnections, port1);
        acceptingClientsThread.detach();
        sleep(1);

        sendtologclosed("Done");



        loginfo("HoneyPi Server has started successfully");

        // NETWORK INFORMATION
        char buffer[BUFFER_SIZE];
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        // MAIN RUNNING LOOP
        while(startupchecks == 0 && encounterederrors == 0) {

            sleep(60);
            loginfo("Running = TRUE...");


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
}