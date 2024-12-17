#include "adminconsole.h"
#include "globalvariables.h"

//int useraccesslevel = 0;
int useraccesslevel = 3;
// TEMPORARY - FIX THIS
// BACKUP OF DATABASES
// UCRYPT START THIS AND HOPEFULLY FINISH THIS!
// other encryptrion method (hacksweep) do this


// USER LEVELS
// USER 3 - MASTER USER
// USER 2 - EDIT DB/ MAINTAIN SERVER
// USER 1 - ACTIVATE 
// USER 0 - TEST COMMANDS ON SERVER

int currentimunte;
int currenthour;
int currentdays;
int currentyear;


////////////////////////////////////
//// USER ACCESS LEVEL COMMANDS ////
////////////////////////////////////
void level3access() {
    std::cout << std::endl;
    std::cout << "Level 3 Access:" << std::endl;

}

void level2access() {
    std::cout << std::endl;
    std::cout << "Level 2 Access:" << std::endl;
    std::cout << "backup      | (NO ARGS) | Backup the Server" << std::endl;
    std::cout << "update      | (NO ARGS) | Update the Server" << std::endl;
    std::cout << "logs        | (NO ARGS) | View All Logs on the Machine" << std::endl;
}

void level1access() {
    std::cout << std::endl;
    std::cout << "Level 1 Access:" << std::endl;
    std::cout << "shutdown    | (NO ARGS) | Shutdown the Server" << std::endl;
}

void level0access() {
    std::cout << std::endl;
    std::cout << "Level 0 Access:" << std::endl;
    std::cout << "commands    | (NO ARGS) | Displays this list of commands" << std::endl;
    std::cout << "generate    | (PI/ROUTER/FILENAME/CLIENTKEY) | Generate a Random Key (Not Assigned)" << std::endl;
    std::cout << "ping        | (NO ARGS) | Ping Internet for Connectivity" << std::endl;
    std::cout << "lock        | (80/443/11829) | Lock Port" << std::endl;
    std::cout << "unlock      | (80/443/11829) | Unlock Port" << std::endl;
}




/////////////////////////////////
//// SEND TO TERMINAL SCRIPT ////
/////////////////////////////////
void sendtoterminal(std::string data) {
    std::cout << data << std::endl;
}

void processCommand(const std::string& command) {
    bool foundcommand = false;

    // SHOW GENERAL HELP IN COMMANDS
    if (command == "commands") {
        switch (useraccesslevel) {
            case 0:
                level0access();
                break;
            case 1:
                level1access();
                level0access();
                break;
            case 2:
                level2access();
                level1access();
                level0access();
                break;
            case 3:
                level3access();
                level2access();
                level1access();
                level0access();
                break;
        }
        foundcommand = true;
    }

    // SERVER STATUS COMMAND
    if (command == "status") {
        std::cout << "Server Status: " << serverStarted.load() << std::endl;
        std::cout << std::endl;
        std::cout << "Thread Status" << std::endl;
        std::cout << "Port 80 Thread: " << statusP80.load() << std::endl;
        std::cout << "Port 443 Thread: " << statusP443.load() << std::endl;
        std::cout << "Port 11829 Thread: " << statusP11829.load() << std::endl;
        std::cout << std::endl;
        std::cout << "Port Lock Status" << std::endl;
        std::cout << "Port 80 Lock: " << lockP80.load() << std::endl;
        std::cout << "Port 443 Lock: " << lockP443.load() << std::endl;
        std::cout << "Port 11829 Lock: " << lockP11829.load() << std::endl;
        std::cout << std::endl;
        std::cout << "Errors" << std::endl;
        std::cout << "General Errors: " << serverErrors.load() << std::endl;
        foundcommand = true;
    }

    // PING THE NETWORK
    if (command == "ping") {
        if (useraccesslevel >= 0) {
            std::cout << "Pinging Internet..." << std::endl;
            int pinger = pingnetwork();
            if (pinger == 0) {
                std::cout << "OK";
            } else {
                std::cout << "ERROR";
            }
        }
        foundcommand = true;
    }

    // UPDATE COMMAND
    if (command == "update") {
        if (useraccesslevel >= 2) {
            updateSIGNAL.store(1);
            std::cout << "THE SERVER IS GOING TO UPDATE NOW!" << std::endl;
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (command == "backup") {
        if (useraccesslevel >= 2) {
            std::cout << "Starting Full System Backup" << std::endl;
            startbackup(1);
        }
        foundcommand = true;
    }

    // SHUTDOWN COMMAND
    if (command == "shutdown") {
        if (useraccesslevel >= 1) {
            stopSIGNAL.store(1);
            std::cout << "THE SERVER IS SHUTTING DOWN NOW!" << std::endl;
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // EXIT TERMINAL BUT KEEP RUNNING IN BACKGROUND
    if (command == "exit") {
        if (useraccesslevel >= 2) {
            std::cout << "Exiting out of shell...\n";
            return;
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // OPEN AND READ LOG FILES
    if (command == "logs") {
        if (useraccesslevel >= 2) {
            readfromlogger();
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }



    // START ANALYZING FIRST WORD IF NOT FOUND
    std::string firstseveral = "";
    std::string firstfour = "";
    if (command.length() >= 8) {
        firstseveral = command.substr(0,8);
        firstfour = command.substr(0,4);
    } else if (command.length() >= 4) {
        firstfour = command.substr(0,4);
    } else {
        firstseveral = command;
        firstfour = command;
    }

    // GENERATE RANDOM STRINGS FOR API TOKENS AND AMONG OTHER THINGS
    if (firstseveral == "generate") {
        if (useraccesslevel >= 0) {
            bool finishcommand = false;
            if (command.length() == 11) {
                std::string togenerate = command.substr(8,3);
                if (togenerate == " PI") {
                    finishcommand = true;
                    std::string randomstring = generateRandomStringHoneyPI();
                    std::cout << "GENERATED PI STRING: " << randomstring << std::endl;
                }
            }
            if (command.length() == 15) {
                std::string togenerate = command.substr(8,7);
                if (togenerate == " ROUTER") {
                    finishcommand = true;
                    std::string randomstring = generateRandomStringRouterAPI();
                    std::cout << "GENERATED ROUTER STRING: " << randomstring << std::endl;
                }
            }
            if (command.length() == 17) {
                std::string togenerate = command.substr(8,9);
                if (togenerate == " FILENAME") {
                    finishcommand = true;
                    std::string randomstring = generateRandomFileName();
                    std::cout << "GENERATED FILE NAME: " << randomstring << std::endl;
                }
            }
            if (command.length() == 18) {
                std::string togenerate = command.substr(8,10);
                if (togenerate == " CLIENTKEY") {
                    finishcommand = true;
                    std::string randomstring = generateRandomClientKey();
                    std::cout << "GENERATED CLIENT TOKEY KEY: " << randomstring << std::endl;
                }
            }

            if (finishcommand == false) {
                std::cout << "No Valid Option Received for Generate" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // LOCK PORTS
    if (firstfour == "lock") {
        std::string port = "";
        if (command.length() == 7) {
            std::string portlock = command.substr(5,2);
            if (portlock == "80") {
                std::cout << "Locked Port 80 (HTTP)" << std::endl;
                lockP80.store(1);
            }
        } else if (command.length() == 8) {
            std::string portlock = command.substr(5,3);
            if (portlock == "443") {
                std::cout << "Locked Port 443 (HTTPS)" << std::endl;
                lockP443.store(1);
            }
        } else if (command.length() == 10) {
            std::string portlock = command.substr(5,5);
            if (portlock == "11829") {
                std::cout << "Locked Port 11829 (API)" << std::endl;
                lockP11829.store(1);
            }
        } else {
            std::cout << "No Valid Option Received" << std::endl;
        }
        foundcommand = true;
    }

    // UNLOCK PORTS
    if (firstfour == "unlo") {
        std::string port = "";
        if (command.length() == 9) {
            std::string portlock = command.substr(7,2);
            if (portlock == "80") {
                std::cout << "Locked Port 80 (HTTP)" << std::endl;
                lockP80.store(0);
            }
        } else if (command.length() == 10) {
            std::string portlock = command.substr(7,3);
            if (portlock == "443") {
                std::cout << "Locked Port 443 (HTTPS)" << std::endl;
                lockP443.store(0);
            }
        } else if (command.length() == 12) {
            std::string portlock = command.substr(7,5);
            if (portlock == "11829") {
                std::cout << "Locked Port 11829 (API)" << std::endl;
                lockP11829.store(0);
            }
        }else {
            std::cout << "No Valid Option Received" << std::endl;
        }
        foundcommand = true;
    }




    // MAKE SURE THE COMMAND IS FOUND
    if (foundcommand == false) {
        std::cout << "Unknown command: " << command << "\n";
        std::cout << "Try 'commands' instead" << std::endl;
    }
}

void interactiveTerminal() {
    sleep(3);
    std::cout << "HoneyPi Terminal" << std::endl;
    std::cout << "HoneyPi Server Version: 0.2.0" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    while (true) {
        std::string command;
        switch (useraccesslevel) {
            case 0:
                std::cout << ">> ";
                break;
            case 1:
                std::cout << "user >> ";
                break;
            case 2:
                std::cout << "admin >> ";
                break;
            case 3:
                std::cout << "sudo >> ";
                break;
        }
        std::getline(std::cin, command);

        if (!command.empty()) {
            processCommand(command);
        }
    }
}