#include "adminconsole.h"
#include "globalvariables.h"

int useraccesslevel = 0;
std::string user = "-";

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

// PREVIOUS COMMAND
std::string previouscommand;


/////////////////////////////////
//// WAIT FOR TERMINAL INPUT ////
/////////////////////////////////
std::string terminalinput(bool sensitive) {
    std::string command;
    std::getline(std::cin, command);
    if (sensitive == false) {
        if (command == "u") {
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
            std::cout << previouscommand << std::endl;
            return previouscommand;
        } else {
            previouscommand = command;
        }
    }
    return command;
}





//////////////////////////////////////
//// PLUS / MINUS COMMANDS HEADER ////
//////////////////////////////////////
void plusminuscommands() {
    std::cout << "+" << std::endl;
    std::cout << "  user      | (USERNAME)| Add a Point to a Username in the UserStream File" << std::endl;
    std::cout << "  pass      | (PASSWORD)| Add a Point to a Password in the PassStream File" << std::endl;
    std::cout << "  comm      | (COMMANDS)| Add a Point to a Command in the CommandStream File" << std::endl;
    std::cout << "  fold      | (FOLDERS) | Add a Point to a Folder in the FolderStream File" << std::endl;
    std::cout << "  flvw      | (FILES)   | Add a Point to a File Viewed in the Stream File" << std::endl;
    std::cout << "  flch      | (FILES)   | Add a Point to a File Edited in the Stream File" << std::endl;
    std::cout << std::endl;
    std::cout << "-" << std::endl;
    std::cout << "  user      | (USERNAME)| Remove a Point to a Username in the UserStream File" << std::endl;
    std::cout << "  pass      | (PASSWORD)| Remove a Point to a Password in the PassStream File" << std::endl;
    std::cout << "  comm      | (COMMANDS)| Remove a Point to a Command in the CommStream File" << std::endl;
    std::cout << "  fold      | (FOLDERS) | Remove a Point to a Folder in the FolderStream File" << std::endl;
    std::cout << "  flvw      | (FILES)   | Remove a Point to a Viewed File in the FileViewStream File" << std::endl;
    std::cout << "  flch      | (FILES)   | Remove a Point to a Edited File in the FileEditStream File" << std::endl;
    return;
}




void ipcommands() {
    std::cout << std::endl;
    std::cout << "IP" << std::endl;
    std::cout << "   RAW      | (IPADDR)  | Read from IP Raw File for IP Address and Report Back" << std::endl;
    std::cout << "   ADD      | (IPADDR)  | Add New Report to an IP Address in File Stream (Only Effects Raw)" << std::endl;
    std::cout << "   NEW      | (IPADDR)  | Add New Report and Link to General IP Files (Adds to IP Lists)" << std::endl;
    std::cout << "   ACHE     | (IPADDR)  | Check for IP Address in Standard File Stream" << std::endl;
    std::cout << "   BCHE     | (IPADDR)  | Check for IP Address in Strict File" << std::endl;
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
    std::cout << "cat         | (NO ARGS) | Read File and Output it To Console" << std::endl;
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
    std::cout << "read443packets   | (NO ARGS) | Read All IP/Packets Combination on Port" << std::endl;
    std::cout << "testreport  | (NO ARGS) | Process the Test Report for Loop Code" << std::endl;
    std::cout << "+           | (NO ARGS) | Display the Plus/Minus Commands" << std::endl;
    std::cout << "-           | (NO ARGS) | Display the Plus/Minus Commands" << std::endl;
}

void level1access() {
    std::cout << std::endl;
    std::cout << "Level 1 Access:" << std::endl;
    std::cout << "shutdown    | (NO ARGS) | Shutdown the Server" << std::endl;
    std::cout << "generate    | (PI/ROUTER/FILENAME/CLIENTKEY) | Generate a Random Key (Not Assigned)" << std::endl;
    std::cout << "ping        | (NO ARGS) | Ping Internet for Connectivity" << std::endl;
    std::cout << "pingdb      | (NO ARGS) | Ping MariaDB to Make Sure it is Working" << std::endl;
    std::cout << "refresh     | (rp,wb)   | Refresh the Cache" << std::endl;
    std::cout << std::endl;
    plusminuscommands();
    ipcommands();
    std::cout << "COMMAND will soon be replaced with non-MariaDB Version that is txt related" << std::endl;
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
        std::cout << "Port 80 Thread:    " << statusP80.load() << std::endl;
        std::cout << "Port 443 Thread:   " << statusP443.load() << std::endl;
        std::cout << "Port 11829 Thread: " << statusP11829.load() << std::endl;
        std::cout << std::endl;
        std::cout << "Port Lock Status" << std::endl;
        std::cout << "Port 80 Lock:    " << lockP80.load() << std::endl;
        std::cout << "Port 443 Lock:   " << lockP443.load() << std::endl;
        std::cout << "Port 11829 Lock: " << lockP11829.load() << std::endl;
        std::cout << std::endl;
        std::cout << "Errors" << std::endl;
        std::cout << "General Errors:   " << serverErrors.load() << std::endl;
        
        std::cout << std::endl << "Statistics" << std::endl;
        std::cout << " - API Rejects:        " << apiRejects.load() << std::endl;
        std::cout << " - New Connections:    " << newConnections.load() << std::endl;
        std::cout << " - Devices Connected:  " << totalDevicesConnected.load() << std::endl;
        std::cout << " - Processing Error:   " << processingErrors.load() << std::endl;
        std::cout << " - Conversion Error:   " << conversionErrors.load() << std::endl;
        std::cout << " - Encryptions         " << encryptionchange.load() << std::endl;
        std::cout << " - Encryption Error:   " << dataEncryptionErrors.load() << std::endl;
        std::cout << " - Invalid Packets:    " << invalidPackets.load() << std::endl;
        std::cout << " - Analyzed Packets:   " << analyzedPackets.load() << std::endl;
        std::cout << " - Clients Denied:     " << clientsDenied.load() << std::endl;
        std::cout << " - COGs Analyzed:      " << cogsAnalyzed.load() << std::endl;
        std::cout << " - Networked Error:    " << networkErrors.load() << std::endl;
        std::cout << " - Entries Saved:      " << entryAdded.load() << std::endl;
        
        foundcommand = true;
    }

    // LOGIN COMMAND
    if (command == "login") {
        system("clear");
        std::cout << "Username: ";
        std::string username = terminalinput(true);
        system("clear");
        std::cout << "Password: ";
        std::string password = terminalinput(true);
        system("clear");
        sleep(1);
        logwarning("Attempted Login @ " + username + "; Pass: " + password, true);
        std::map<int, std::string> result = logincredentials(username, password);
        if (result[0] == "1") {
            useraccesslevel = stringtoint(result[1]);
            user = result[2];
            std::cout << "Login was Successful" << std::endl;
            loginfo("Login Successful", true);
        } else {
            useraccesslevel = 0;
            user = "-";
            std::cout << "Login DENIED!" << std::endl;
            logwarning("Login DENIED @ " + username + "; Pass: " + password, true);
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

    // SYSTEM BACKUP
    if (command == "backup") {
        if (useraccesslevel >= 2) {
            std::cout << "Starting Full System Backup" << std::endl;
            startbackup(1);
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // REFRESH TO CACHE INTO RAM
    if (command == "refresh") {
        if (useraccesslevel >= 1) {
            if (command.length() == 10) {
                std::string typeRAM = command.substr(8,2);
                if (typeRAM == "rp") {
                    std::cout << "Caching Report into RAM..." << std::endl;
                    std::map<int, std::map<std::string, float>> returnweb = cacheseverity();
                    if (returnweb[0]["ERROR"] != -1) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "FAILED" << std::endl;
                    }
                } else if (typeRAM == "wb") {
                    std::cout << "Caching HTML into RAM..." << std::endl;
                    int returnweb = loadHTMLINTORAM();
                    if (returnweb != 0) {
                        std::cout << "Caching Returned " << returnweb << std::endl;
                    } else {
                        std::cout << "Success" << std::endl;
                    }
                } else {
                    std::cout << "No Valid Type!" << std::endl;
                }
            } else {
                std::cout << "No Valid Type!" << std::endl;
            }
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
                std::cout << "IP: " << pair.first << ", Packets: " << pair.second << std::endl;
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

    // PROCESS THE TEST COMMAND AND VERIFY
    if (command == "testreport" || command == "testreport f") {
        if (useraccesslevel >= 2) {
            std::cout << "Starting Interaction with Test Report" << std::endl;
            int returnvalue = -100;
            if (command == "testreport f") {
                returnvalue = processReport("/home/testreport.txt", "localhost", false, "");
            } else {
                returnvalue = processReport("/home/testreport.txt", "localhost", true, "");
            }

            if (returnvalue != 0) {
                std::cout << "Received Return Value of " << returnvalue << " while trying to process!" << std::endl;
            } else {
                std::cout << "Processed Successfully" << std::endl;
            }
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
        user = "-";
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

    // TEST IPSTRING FUNCTION
    if (firstseveral == "ipstring") {
        if (useraccesslevel >= 1) {
            if (command.length() > 15) {
                std::cout << "RETURNED FROM IPSTRING: " << ipstring(command.substr(9, command.length() - 9)) << std::endl;
            }
        }
    }

    // READ FROM FILE THROUGH SYSTEM 
    if (firstfour == "cat ") {
        //std::string restofcommand = "cat " + command.substr(4,command.length());
        system(command.c_str());
        foundcommand = true;
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
                        std::string newdata = terminalinput(true);
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
                        std::string newdata = terminalinput(true);
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

    // THE IP COMMANDS
    if (firstthree == "IP ") {
        if (useraccesslevel >= 1) {
            if (command.length() >= 10) {
                std::string subco = command.substr(3,4);
                
                if (subco == "RAW ") {
                    std::cout << "IP:" << command.substr(7) << std::endl;
                    std::map<int, std::string> returnedvalues = readfromipraw(command.substr(7));
                    if (returnedvalues[0] == "NULL") {
                        std::cout << "IP Not Found in DB" << std::endl;
                    } else if (returnedvalues[0] == "ERROR") {
                        std::cout << "ERROR" << std::endl;
                    } else {
                        std::cout << "RECEIVED" << std::endl;
                        
                        // TIME COMPARITORS
                        const time_t newestpacket = static_cast<const time_t> (stringtoint(returnedvalues[2]));
                        const time_t firstpack = static_cast<const time_t> (stringtoint(returnedvalues[3]));

                        // REPORTING INFORMATION
                        std::cout << "IP Address in File       | " << returnedvalues[0] << "|" << std::endl;
                        std::cout << "Severity Last 30 Reports | " << returnedvalues[1] << "|" << std::endl;
                        std::cout << "Newest Packet Time       | " << ctime(&newestpacket);
                        std::cout << "First Packet             | " << ctime(&firstpack);
                        std::cout << "Number of Reports        | " << returnedvalues[4] << "|" << std::endl;
                        std::cout << "Max Severity Recorded    | " << returnedvalues[5] << "|" << std::endl;
                        std::cout << "Min Severity Recorded    | " << returnedvalues[6] << "|" << std::endl;
                        std::cout << "Mean Severity            | " << returnedvalues[7] << "|" << std::endl;
                        std::cout << "Developer Ban of IP      | " << returnedvalues[8] << "|" << std::endl;
                        std::cout << "Permanent Ban of IP      | " << returnedvalues[9] << "|" << std::endl;
                        std::cout << "Lifted Ban for IP        | " << returnedvalues[10] << "|" << std::endl;
                        std::cout << "Associated with HoneyPi  | " << returnedvalues[11] << "|" << std::endl;
                        std::cout << "Number of Reports (Today)| " << returnedvalues[12] << "|" << std::endl;
                        std::cout << "Days Since Last Report   | " << returnedvalues[13] << "|" << std::endl;
                        std::cout << "Notes                    | " << returnedvalues[14] << "|" << std::endl;
                        std::cout << std::endl;
                        std::cout << "Position in File         | " << returnedvalues[100] << std::endl;
                        std::cout << "Length of Entry          | " << returnedvalues[101] << std::endl;
                    }
                }

                if (subco == "ADD ") {

                    std::cout << "IP:" << command.substr(7, command.length()) << std::endl;
                    std::map<int, float> returnedvalues = saveiptoTIMEBASEDFILE(command.substr(7, command.length()), 10, false);

                }

                if (subco == "NEW ") {
                    std::string ipaddstring = command.substr(7, command.length());
                    std::cout << "IP:" << ipaddstring << std::endl;
                    //std::map<int, float> returnedvalues = saveiptoTIMEBASEDFILE(command.substr(7, command.length()), 10, false);
                    std::map<int, std::string> ipaddrs;
                    std::map<int, std::map<std::string, float>> severity;
                    ipaddrs[0] = ipaddstring;
                    severity[0][ipaddstring] = 10;
                    int returned = saveipaddrPREMIUMFILE(ipaddrs, severity, false);
                    if (returned >= 0) {
                        std::cout << "OK" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    }
                }
                
                if (subco == "ACHE") {
                    std::cout << "IP:" << command.substr(8, command.length()) << std::endl;
                    int returnedvalues = ipinstandardfile(command.substr(8, command.length()));
                    if (returnedvalues == 0) {
                        std::cout << "N/A" << std::endl;
                    } else if (returnedvalues == 1) {
                        std::cout << "FOUND" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    }
                }

                if (subco == "BCHE") {
                    std::cout << "IP:" << command.substr(8, command.length()) << std::endl;
                    int returnedvalues = ipinstrictfile(command.substr(8, command.length()));
                    if (returnedvalues == 0) {
                        std::cout << "N/A" << std::endl;
                    } else if (returnedvalues == 1) {
                        std::cout << "FOUND" << std::endl;
                    } else {
                        std::cout << "ERROR" << std::endl;
                    }
                }
                
                std::string catcommand = "cat /home/listfiles/iplistraw.txt";
                system(catcommand.c_str());

            
            } else {
                std::cout << "No Valid Options Received" << std::endl;
            }
        } else {
             std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    // THE FILE COMMANDS
    if (command == "+" || command == "-") {
        if (useraccesslevel >= 2) {
            plusminuscommands();
        }
        foundcommand = true;
    }

    if (firstthree == "+ u") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "+ user ") {
                    std::map<int, std::string> userbase;
                    userbase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = saveusernamestofile(userbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '+'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "+ p") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "+ pass ") {
                    std::map<int, std::string> passbase;
                    passbase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = savepasswordstofile(passbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '+'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "+ c") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "+ comm ") {
                    std::map<int, std::string> commbase;
                    commbase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = savecommandstofile(commbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '+'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "+ f") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "+ fold ") {
                    std::map<int, std::string> foldbase;
                    foldbase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = savefoldertofile(foldbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else if (firstseveral.substr(0,7) == "+ flvw ") {
                    std::map<int, std::string> filebase;
                    filebase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = savefilesviewedtofile(filebase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else if (firstseveral.substr(0,7) == "+ flch ") {
                    std::map<int, std::string> filebase;
                    filebase[0] = command.substr(7, command.length() - 7);
                    int returnvalue = savefileeffectstofile(filebase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '+'" << std::endl;
                }
            } 
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "- u") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "- user ") {
                    std::string userbase;
                    userbase = command.substr(7, command.length() - 7);
                    int returnvalue = removeusernamefromfile(userbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '-'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "- p") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "- pass ") {
                    std::string passbase;
                    passbase = command.substr(7, command.length() - 7);
                    int returnvalue = removepasswordfromfile(passbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '-'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    if (firstthree == "- c") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "- comm ") {
                    std::string commbase;
                    commbase = command.substr(7, command.length() - 7);
                    int returnvalue = removecommandfromfile(commbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '-'" << std::endl;
                }
            }
        } else {
            std::cout << "Sorry, you do not have permissions to perform this action." << std::endl;
        }
        foundcommand = true;
    }

    
    if (firstthree == "- f") {
        if (useraccesslevel >= 1) {
            if (firstseveral.length() == 8) {
                if (firstseveral.substr(0,7) == "- fold ") {
                    std::string foldbase;
                    foldbase = command.substr(7, command.length() - 7);
                    int returnvalue = removefolderfromfile(foldbase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else if (firstseveral.substr(0,7) == "- flvw ") {
                    std::string filebase;
                    filebase = command.substr(7, command.length() - 7);
                    int returnvalue = removefileviewfromfile(filebase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else if (firstseveral.substr(0,7) == "- flch ") {
                    std::string filebase;
                    filebase = command.substr(7, command.length() - 7);
                    int returnvalue = removefileeffectfromfile(filebase, false);
                    if (returnvalue != 1) {
                        std::cout << "INSERT Returned " << returnvalue << std::endl;
                    } else {
                        std::cout << "OK" << std::endl;
                    }
                } else {
                    std::cout << "INVALID OPTION FOR '-'" << std::endl;
                }
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
        command = terminalinput(false);
        logconsole("Received Command: " + command, true);

        if (command.empty() != true) {
            processCommand(command);
        }
    }
}