#include "adminconsole.h"
#include "globalvariables.h"

int useraccesslevel = 0;

// BACKUP OF DATABASES


// USER LEVELS
// USER 3 - MASTER USER
// USER 2 - EDIT DB/ MAINTAIN SERVER
// USER 1 - ACTIVATE 
// USER 0 - TEST COMMANDS ON SERVER

int currentimunte;
int currenthour;
int currentdays;
int currentyear;


/////////////////////////////////
//// WAIT FOR TERMINAL INPUT ////
/////////////////////////////////
std::string terminalinput() {
    std::string command;
    std::getline(std::cin, command);
    return command;
}



////////////////////////////////////
//// USER ACCESS LEVEL COMMANDS ////
////////////////////////////////////
void level3access() {
    std::cout << std::endl;
    std::cout << "Level 3 Access:" << std::endl;
    std::cout << "system      | (NO ARGS) | Enter System Level" << std::endl;
}

void level2access() {
    std::cout << std::endl;
    std::cout << "Level 2 Access:" << std::endl;
    std::cout << "backup      | (NO ARGS) | Backup the Server" << std::endl;
    std::cout << "update      | (NO ARGS) | Update the Server" << std::endl;
    std::cout << "logs        | (NO ARGS) | View All Logs on the Machine" << std::endl;
    std::cout << "packetlogs  | (NO ARGS) | View All Packet Logs on the Machine" << std::endl;
    std::cout << "menc        | (STRING)  | Determine Encryption Method of String" << std::endl;
    std::cout << "ecrypt      | (MESSAGE) | Message to Encrypt Using UCRYPT Key" << std::endl;
    std::cout << "uncrypt     | (MESSAGE) | Message to Decrypt Using UCRYPT Key" << std::endl;
    std::cout << "hacksweep   | (decrypt/encrypt) | Open Command for Hacksweep Decryption/Encryption" << std::endl;
    std::cout << "lock        | (80/443/11829) | Lock Port" << std::endl;
    std::cout << "unlock      | (80/443/11829) | Unlock Port" << std::endl;
    std::cout << "read11829packets | (NO ARGS) | Read All IP/Packets Combination on Port" << std::endl;
    std::cout << "read443packets | (NO ARGS) | Read All IP/Packets Combination on Port" << std::endl;
}

void level1access() {
    std::cout << std::endl;
    std::cout << "Level 1 Access:" << std::endl;
    std::cout << "shutdown    | (NO ARGS) | Shutdown the Server" << std::endl;
    std::cout << "IP CHECK    | (IPADDR)  | Check for IP in Server DB [Not IPLIST]" << std::endl;
    std::cout << "IP ADD      | (IPADDR)  | Add IP into Server DB [NOT IPLIST]" << std::endl;
    std::cout << "IP REMOVE   | (IPADDR)  | Remove IP Address from Server DB [Not IPLIST]" << std::endl;
    std::cout << "IP BLOCK    | (IPADDR)  | Block IP Address in Server DB [Not IPLIST]" << std::endl;
    std::cout << "IP UBLOCK   | (IPADDR)  | Unblock IP Address in Server DB [Not IPLIST]" << std::endl;
    std::cout << "IP READDEV  | (IPADDR)  | Read the Developer Banned Block of IP Address" << std::endl;
    std::cout << "IP PACKET   | (-#/+#);(IPADDR) | Add/Subtract Packets from IPADDR" << std::endl;
    std::cout << "generate    | (PI/ROUTER/FILENAME/CLIENTKEY) | Generate a Random Key (Not Assigned)" << std::endl;
    std::cout << "ping        | (NO ARGS) | Ping Internet for Connectivity" << std::endl;
    std::cout << "pingdb      | (NO ARGS) | Ping MariaDB to Make Sure it is Working" << std::endl;
}

void level0access() {
    std::cout << std::endl;
    std::cout << "Level 0 Access:" << std::endl;
    std::cout << "commands    | (NO ARGS) | Displays this list of commands" << std::endl;
    std::cout << "status      | (NO ARGS) | Status of Server Command" << std::endl;
    std::cout << "login       | (NO ARGS) | Login with Higher User" << std::endl;
    std::cout << "logout      | (NO ARGS) | Log Out of Console" << std::endl;
    std::cout << "clear       | (NO ARGS) | Clear the Terminal" << std::endl;
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

    // LOGIN COMMAND
    if (command == "login") {
        system("clear");
        std::cout << "Username: ";
        std::string username = terminalinput();
        system("clear");
        std::cout << "Password: ";
        std::string password = terminalinput();
        system("clear");
        sleep(1);
        logwarning("Attempted Login @ " + username + "; Pass: " + password, true);
        int result = logincredentials(username, password);
        if (result != 0) {
            useraccesslevel = result;
            std::cout << "Login was Successful" << std::endl;
            loginfo("Login Successful", true);
        } else {
            useraccesslevel = 0;
            std::cout << "Login DENIED!" << std::endl;
            logcritical("Login DENIED @ " + username + "; Pass: " + password, true);
        }
        sleep(3);
        system("clear");
        foundcommand = true;
    }

    // PING THE NETWORK
    if (command == "ping") {
        if (useraccesslevel >= 1) {
            std::cout << "Pinging Internet..." << std::endl;
            int pinger = pingnetwork();
            if (pinger == 0) {
                std::cout << "OK" << std::endl;
            } else {
                std::cout << "ERROR" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // PING MARIADB
    if (command == "pingdb") {
        foundcommand = true;
        if (useraccesslevel >= 1) {
            std::cout << "Pinging DB..." << std::endl;
            int resultant = mariadb_ping();
            if (resultant == 0) {
                std::cout << "OK" << std::endl;
            } else {
                std::cout << "ERROR" << std::endl;
            }
        } else {
             std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
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
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
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

    // PACKET LOGS COMMAND
    if (command == "packetlogs") {
        if (useraccesslevel >= 2) {
            readfrompacketlogger();
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }
    
    // READ ALL PACKETS FROM IP ADDRESS/PACKET COMBO IN 11829 MAP
    if (command == "read11829packets") {
        if (useraccesslevel >= 2) {
            std::cout << "11829 PACKETS MAP" << std::endl;
            for (const auto& pair : ip11829) {
                std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // READ ALL PACKETS FROM IP ADDRESS/PACKET COMBO IN 443 MAP
    if (command == "read443packets") {
        if (useraccesslevel >= 2) {
            std::cout << "443 PACKETS MAP" << std::endl;
            for (const auto& pair : ip443) {
                std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // ENTER BASH OF SYSTEM
    if (command == "system") {
        if (useraccesslevel >= 3) {
            std::cout << "TRANSFERRING TO SYSTEM!" << std::endl;
            std::cout << "Type 'exit' to return" << std::endl;
            sleep(2);
            system("bash2");
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // LOGOUT OF CONSOLE
    if (command == "logout") {
        std::cout << "Logging out..." << std::endl;
        sleep(1);
        system("clear");
        sleep(1);
        foundcommand = true;
        useraccesslevel = 0;
    }



    // START ANALYZING FIRST WORD IF NOT FOUND
    std::string firstseveral = "";
    std::string firstfour = "";
    if (command.length() >= 8 && foundcommand == false) {
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
        if (useraccesslevel >= 1) {
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

    // HACKSWEEP ENCRYPTION/DECRYPTION
    if (firstseveral == "hackswee") {
        if (useraccesslevel >= 2) {
            if (command.length() == 17) {
                std::string method = command.substr(10,7);
                if (method == "encrypt") {
                    bool completioncrypt = false;
                    std::string datatosend = "";
                    while (completioncrypt == false) {
                        std::string newdata = terminalinput();
                        if (newdata == "end") {
                            completioncrypt = true;
                        } else {
                            datatosend = datatosend + "/n" + newdata;
                        }
                    }
                    std::string term = hacksweep_Ecrypt(datatosend);
                    std::cout << "Received Encrypted String (Hacksweep) of: " << term << std::endl;
                } else if (method == "decrypt") {
                    bool completioncrypt = false;
                    std::string datatosend = "";
                    while (completioncrypt == false) {
                        std::string newdata = terminalinput();
                        if (newdata == "end") {
                            completioncrypt = true;
                        } else {
                            datatosend = datatosend + "/n" + newdata;
                        }
                    }
                    std::string term = hacksweep_decrypt(datatosend);
                    std::cout << "Received Decrypted String (Hacksweep) of: " << term << std::endl;                    
                } else {
                    std::cout << "Not Valid" << std::endl;
                }
            } else if (command.length() > 17) {
                std::string method = command.substr(10,7);
                if (method == "decrypt") {
                    std::string datatocrypt = command.substr(18, command.length() - 18);
                    std::string reult = hacksweep_decrypt(datatocrypt);
                    std::cout << "Received Decrypted String (Hacksweep) of: " << std::endl;
                } else if (method == "encrypt") {
                    std::string datatocrypt = command.substr(18, command.length() - 18);
                    std::string result = hacksweep_Ecrypt(datatocrypt);
                    std::cout << "Received Encrypted String (Hacksweep) of: " << result << std::endl;
                }
            } else {
                std::cout << "No Args Passed!" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // LOCK PORTS
    if (firstfour == "lock") {
        if (useraccesslevel >= 2) {
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
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // UNLOCK PORTS
    if (firstfour == "unlo") {
        if (useraccesslevel >= 2) {
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
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // WHICH ENCRYPTION METHOD
    if (firstfour == "menc") {
        if (useraccesslevel >= 2) {
            std::cout << "Analyzing Encrypted String" << std::endl;
            std::string datatoload = command.substr(5, command.length() - 5);
            int results = encryptionmethod(datatoload, 1);
            if (results == 1) {
                std::cout << "HACKSWEEP ENCRYPTION" << std::endl;
            } else if (results == 2) {
                std::cout << "UCRYPT ENCRYPTION" << std::endl;
            } else {
                std::cout << "AN ERROR OCCURRED ANALYZING!" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // ENCRYPTION USING UCRYPT
    if (firstfour == "ecry") {
        if (useraccesslevel >= 2) {
            if (command.length() > 7) {
                std::cout << "Encrypting String Using UCRYPT..." << std::endl;
                std::string messagetoencrypt = command.substr(7, command.length() - 7);
                std::string result = ucrypt_Ecrypt(messagetoencrypt);
                std::cout << "Generated Message (UCRYPT): " << result << std::endl;
            } else {
                std::cout << "No Arguments Passed" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // DECRYPTION USING UCRYPT
    if (firstfour == "uncr") {
        if (useraccesslevel >= 2) {
            if (command.length() > 8) {
                std::cout << "Decrypting String Using UCRYPT..." << std::endl;
                std::string messagetodecrypt = command.substr(8, command.length() - 8);
                std::string result = ucrypt_decrypt(messagetodecrypt);
                std::cout << "Generated Message (UCRYPT): " << result << std::endl;
            } else {
                std::cout << "No Arguments Passed" << std::endl;
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // MARIADB COMMANDS
    std::string firstthree = "";
    if (command.length() >= 3 && foundcommand == false) {
        firstthree = command.substr(0,3);
    }

    if (firstthree == "IP ") {
        if (useraccesslevel >= 1) {
            if (command.length() >= 10) {
                std::string subco = command.substr(3,4);
                
                // IP CHECK FOR CHECK
                if (subco == "CHEC") {
                    std::cout << "Checking for IP" << std::endl;
                    std::string iptocheck = command.substr(9, command.length() - 9);
                    int resultant = mariadb_CHECKIPADDR(iptocheck);
                    if (resultant == 1) {
                        std::cout << "IP Address is in Range" << std::endl;
                    } else {
                        std::cout << "IP Address Not Found" << std::endl;
                    }
                
                // IP CHECK FOR ADD
                } else if (subco == "ADD ") {
                    std::cout << "Adding IP" << std::endl;
                    std::string iptocheck = command.substr(7, command.length() - 7);
                    int resultant = mariadb_ADDIPADDR(iptocheck);
                    if (resultant == 0) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    } 
                // IP CHECK FOR REMOVE
                } else if (subco == "REMO") {
                    std::cout << "Removing IP" << std::endl;
                    std::string iptocheck = command.substr(10, command.length() - 10);
                    int resultant = mariadb_REMOVEOLDIPADDR(iptocheck);
                    if (resultant == 0) {
                        std::cout << "IP Address Removed" << std::endl;
                    } else {
                        std::cout << "ERROR Removing IP Address" << std::endl;
                    }
                // IP CHECK FOR BLOCK
                    // FIX THIS BY ADDING NUMBEROFPACKETSCHANGEDANDMORE  ip block 1
                } else if (subco == "BLOC") {
                    std::cout << "Blocking IP" << std::endl;
                    std::string iptocheck = command.substr(9, command.length() - 9);
                    int resultant = mariadb_BLOCKIPADDR(iptocheck);
                    if (resultant == 0) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    } 
                // IP CHECK FOR UNBLOCK
                } else if (subco == "UBLO") {
                    std::cout << "Unblocking IP" << std::endl;
                    std::string iptocheck = command.substr(11, command.length() - 11);
                    int resultant = mariadb_UNBLOCKIPADDR(iptocheck);
                    if (resultant == 0) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    } 
                } else if (subco == "READ") {
                    std::cout << "Reading DEV Block of IP" << std::endl;
                    std::string iptocheck = command.substr(12, command.length() - 12);
                    bool resultant = mariadb_READDEVBLOCK(iptocheck);
                    if (resultant == true) {
                        std::cout << "DEV Block = Banned!" << std::endl;
                    } else {
                        std::cout << "DEV Block not found or false" << std::endl;
                    } 
                } else if (subco == "PACK") {
                    std::cout << "Adjusting Packets of IP" << std::endl;
                    std::string symbol = command.substr(10, 1);
                    int symbolmath = 0;
                    if (symbol == "-") {
                        symbolmath = 1;
                    } else if (symbol == "+") {
                        symbolmath = 2;
                    } else {
                        std::cout << "No Valid Option Received" << std::endl;
                    }

                    int resultant = 3;

                    if (symbolmath != 0) {
                        std::string numberofpackets = command.substr(11, 1);
                        int numberoftimes = stringtoint(numberofpackets);
                        std::string iptocheck = command.substr(12, command.length() - 12);
                        int numberofcalls = 0;
                        if (symbolmath == 1) {
                            while (numberofcalls < numberoftimes) {
                                resultant = mariadb_REMOVEPACKETFROMIPADDR(iptocheck);
                                numberofcalls = numberofcalls + 1;
                            }
                        } else if (symbolmath == 2) {
                            while (numberofcalls < numberoftimes) {
                                resultant = mariadb_ADDPACKETTOIPADDR(iptocheck);
                                numberofcalls = numberofcalls + 1;
                            }
                        }
                    }

                    if (resultant == 0) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    }
                }
            } else {
                std::cout << "No Valid Options Received" << std::endl;
            }
        } else {
             std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }



    // MAKE SURE THE COMMAND IS FOUND
    if (foundcommand == false) {
        std::cout << "Unknown command: " << command << "\n";
        std::cout << "Try 'commands' instead" << std::endl;
    }
}



// MAIN INTERACTIVE TERMINAL COMMAND
void interactiveTerminal() {
    sleep(10);
    system("clear");
    std::cout << "HoneyPi Terminal" << std::endl;
    std::cout << "HoneyPi Server Version: " << honeyversion << std::endl;
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
        command = terminalinput();
        sendtolog("[CONSOLE] - Received Command: " + command);

        if (command.empty() != true) {
            processCommand(command);
        }
    }
}