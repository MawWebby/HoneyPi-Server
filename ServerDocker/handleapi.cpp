#include "handleapi.h"
#include "globalvariables.h"




// API VARIABLES
const std::string apireject = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 17\n\n{state: rejected}";
const std::string apiincomplete = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 19\n\n{state: incomplete}";
const std::string apisendcog = "HAPI/1.1 200 OK\nContent-Type:text/json\nContent-Length: 13\n\n{state: send}";
const std::string apiwaittosend = "HAPI/1.1 222 OK\nContent-Type:text/json\nContent-Length: 13\n\n{state: wait}";
const std::string apideny = "HAPI/1.1 400 OK\nContent-Type:test/json\nContent-Length: 15\n\n{state: denied}";
const std::string apiunavailable = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 20\n\n{state: unavailable}";
const std::string apiavailable = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 18\n\n{state: available}";
const std::string apinotfound = "HAPI/1.1 404 OK\nContent-Type:text/json\n\nContent-Length: 17\n\n{state: notfound}";
const std::string apitrigger = "HAPI/1.1 200 OK\nContent-Type:text/json\n\nContent-Length:18\n\n{state: triggered}";
const std::string apisuccess = "HAPI/1.1 200 OK\nContent-Type:text/json\nContent-Length: 17\n\n{state: success}";
const std::string apisendliststandard = "HAPI/1.1 200 OK\nContent-Type:text/text\nContent-Length: ";
const std::string apisendlist2standard = "\n\n{state: success; crypt: ";
const std::string apisendlist3standard = "; let: ";
const std::string apisendlist4standard = "}";




////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (11829) - MAIN API SERVER //
////////////////////////////////////////////////////////////
// PROCESS THE API REQUESTS
int processAPI(int clientID, std::string header1, std::string data1, std::string header2, 
               std::string data2, std::string header3, std::string data3, 
               std::string header4, std::string data4, std::string header5, 
               std::string data5, std::string header6, std::string data6, 
               std::string header7, std::string data7, std::string header8, 
               std::string data8, std::string header9, std::string data9) {
    
    // START PROCESSING HERE
    bool completedprocessing = false;
    std::cout << header1 << ":" << data1 << ":" << header2 << ":" << data2 << std::endl;

    sendtolog(header1 + "|");
    sendtolog(data1 + "|");

    // MAIN HEADER RELATING TO HONEYPOT/HONEYPI CONNECTIONS
    if (header1 == "CONNECTION") {
        // MAIN CONNECTION FOR NEW HONEYPIS
        if (data1 == "NEW") {
            // ADD CONDITIONS BASED ON SERVER STATUS AND OTHER THINGS
            // int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
            int updatesig = updateSIGNAL.load();
            int stopsig = stopSIGNAL.load();
            int statusPort = statusP11829.load();

            if (updatesig == 0 && stopsig == 0 && statusPort == 1) {
                int send_res=send(clientID,apiavailable.c_str(),apiavailable.length(),0);
                completedprocessing = true;
            } else {
                int send_res=send(clientID,apiunavailable.c_str(),apiunavailable.length(),0);
                completedprocessing = true;
            }
            return 0;
        }

        // ESTABLISH CONNECTION AND VERIFY API KEYS; CREATE NEW TOKEN KEYS
        if (data1 == "ESTABLISH") {
            if (header2 == "LOGIN" && data2.length() == 68) {
                if (data2.substr(0,4) == "API=") {
                    std::string apiKEY = data2.substr(4,64);
                    std::string newTOKEN;

                    // MAP OPERATIONS
                    if (honeypotauthtotoken.find(apiKEY)->second == "") {
                        newTOKEN = generateRandomStringHoneyPI();
                        honeypotauthtotoken[apiKEY] = newTOKEN;
                    } else {
                        if (honeypotauthtotoken.find(apiKEY)->second.length() == 64) {
                            if (previoushoneypotauth.find(apiKEY)->second.length() != 64) {
                                previoushoneypotauth[apiKEY] = honeypotauthtotoken[apiKEY];
                            } else {
                                previoushoneypotauth2[apiKEY] = previoushoneypotauth[apiKEY];
                                previoushoneypotauth[apiKEY] = honeypotauthtotoken[apiKEY];
                            }
                            newTOKEN = honeypotauthtotoken.find(apiKEY)->second;
                        } else {
                            newTOKEN = generateRandomStringHoneyPI();
                            previoushoneypotauth[apiKEY] = honeypotauthtotoken[apiKEY];
                            honeypotauthtotoken[apiKEY] = newTOKEN;
                        }
                    }
                    
                    std::string data3 = "HAPI/1.1 200 OK\nContent-Type:text/json\nContent-Length: 90\n\n{state: success; TOKEN: " + newTOKEN + "}";
                    int send_res=send(clientID,data3.c_str(),data3.length(),0);
                } else {
                    int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
                }
            } else {
                int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
            }
        }

        // CHECK FOR UPDATES SCRIPT
        if (data1 == "CHECK_FOR_UPDATE") {

        }

        // UPDATE IP LIST AND SEND TO CLIENT
        if (data1 == "UPDATE") {

        }

        // REPORT HONEYPOT CONNECTED CORRECTLY TO INTERNET
        if (data1 == "REPORT") {
            // ADD CONDITIONS BASED ON SERVER STATUS AND OTHER THINGS
            // int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
            int updatesig = updateSIGNAL.load();
            int stopsig = stopSIGNAL.load();
            int statusPort = statusP11829.load();

            if (updatesig == 0 && stopsig == 0 && statusPort == 1) {
                int send_res=send(clientID,apiavailable.c_str(),apiavailable.length(),0);
                completedprocessing = true;
            } else {
                int send_res=send(clientID,apiunavailable.c_str(),apiunavailable.length(),0);
                completedprocessing = true;
            }
            return 0;
        }

        // HONEYPOT SENDING REPORT TO SERVER
        if (data1 == "NEW_REPORT") {
            // VERIFY IT IS ENCRYPTED
            if (header2 == "METHOD" && header3 == "DATA") {
                // DETERMINE THE METHOD OF ENCRYPTION
                std::string decoded;
                int keyshift = encryptionmethod(data3, 0);
                // POSITIVE NUMBER = STANDARD CHARACTER MAP SHIFT
                // NEGATIVE NUMBER = ECRYPTCOG
                if (keyshift == 1) {
                    decoded = hacksweep_decrypt(data3);
                } else if (keyshift == 2) {
                    decoded = ucrypt_decrypt(data3);
                } else {
                    // FAILED CONDITION!
                    logwarning("Received Invalid Packet to Decode", true);
                    return 30;
                }


                // DECODED PORTIONS START HERE!!!
            }
        }

        // HONEYPOT IN MIDDLE OF SENDING LARGE HACKER REPORT
        if (data1 == "REPORT_PART") {
            
        }
    } else if (header1 == "LOGIN") {
        // DIFFERENT LOGIN METHODS ASSOCIATED HERE
        
    }


    if (completedprocessing == false) {
        return 1;
    } else {
        return 0;
    }
    return 255;
}

// ANALYZE THE API REQUESTS
int analyzeAPIandexecute(int clientID, std::string messageA) {
    sendtolog("ANALYZING");
    sendtolog(messageA);
    std::string message = messageA;
    std::string charactertoanalyze = "";
    std::string charactertoanalyze2 = "";
    std::string doublequote = "\"";
    std::string firstheader = "";
    std::string firstdataheader = "";
    std::string secondheader = "";
    std::string seconddataheader = "";
    std::string thirdheader = "";
    std::string thirddataheader = "";
    std::string fourthheader = "";
    std::string fourthdataheader = "";
    std::string fifthheader = "";
    std::string fifthdataheader = "";
    std::string currentvalue = "";

    if (message.length() >= 15) {
        charactertoanalyze = message.substr(0,1);
        charactertoanalyze2 = message.substr(1,1);

        // CHECK FOR JSON CONFIG
        if (charactertoanalyze == "{" && charactertoanalyze2 == doublequote) {
            int characteranalyzing = 2;
            int charactertwoanalyzing = 3;
            int charactertoanalyzemax = message.length();
            int previousmarker = 2;

            bool completedapiread = false;

            // SORT ARGUMENTS INTO SUB-CATEGORIES
            while (completedapiread == false && characteranalyzing <= message.length()) {
                if (message.length() >= characteranalyzing + 1) {
                    charactertoanalyze = message.substr(characteranalyzing, 1);
                    charactertoanalyze2 = message.substr(characteranalyzing + 1, 1);

                    // ANALYZE THE LETTERS TO A RESULT
                    if (charactertoanalyze == "\"" && charactertoanalyze2 == ",") {
                        std::string headerlength = message.substr(previousmarker, characteranalyzing - previousmarker);
                        sendtolog("CURRENT STRING");
                        sendtolog(headerlength);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing;

                        if (firstheader == "") {
                            firstheader = headerlength;
                        } else {
                            if (secondheader == "") {
                                secondheader = headerlength;
                            } else {
                                if (thirdheader == "") {
                                    thirdheader = headerlength;
                                } else {
                                    if (fourthheader == "") {
                                        fourthheader = headerlength;
                                    } else {
                                        if (fifthheader == "") {
                                            fifthheader = headerlength;
                                        } else {
                                            sendtolog("OVERFLOW ERROR IN HAPI PARSER!");
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                        previousmarker = previousmarker + 3;
                    }

                    // ANALYZE DATA HANDLERS TO RESULT
                    if (charactertoanalyze == "\"" && charactertoanalyze2 == ";") {
                        std::string dataheaderlength = message.substr(previousmarker, characteranalyzing - previousmarker);
                        sendtolog("CURRENT DATA_STRING");
                        sendtolog(dataheaderlength);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing;

                        if (firstdataheader == "") {
                            firstdataheader = dataheaderlength;
                        } else {
                            if (seconddataheader == "") {
                                seconddataheader = dataheaderlength;
                            } else {
                                if (thirddataheader == "") {
                                    thirddataheader = dataheaderlength;
                                } else {
                                    if (fourthdataheader == "") {
                                        fourthdataheader = dataheaderlength;
                                    } else {
                                        if (fifthdataheader == "") {
                                            fifthdataheader = dataheaderlength;
                                        } else {
                                            sendtolog("OVERFLOW ERROR IN HAPI PARSER!");
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                        previousmarker = previousmarker + 3;
                    }

                    if (charactertoanalyze == "\"" && charactertoanalyze2 == "}") {
                        std::string dataheaderlength = message.substr(previousmarker, characteranalyzing - previousmarker);
                        sendtolog("CURRENT DATA_STRING");
                        sendtolog(dataheaderlength);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing;

                        if (firstdataheader == "") {
                            firstdataheader = dataheaderlength;
                        } else {
                            if (seconddataheader == "") {
                                seconddataheader = dataheaderlength;
                            } else {
                                if (thirddataheader == "") {
                                    thirddataheader = dataheaderlength;
                                } else {
                                    if (fourthdataheader == "") {
                                        fourthdataheader = dataheaderlength;
                                    } else {
                                        if (fifthdataheader == "") {
                                            fifthdataheader = dataheaderlength;
                                        } else {
                                            sendtolog("OVERFLOW ERROR IN HAPI PARSER!");
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                        previousmarker = previousmarker + 2;
                        completedapiread = true;
                    }
                } else {
                    sendtolog("A PARSER ERROR OCCURRED IN HAPI!");
                }

                characteranalyzing = characteranalyzing + 1;
            }


            // MAKE SURE DATA IS APPLICABLE AND CORRECT
            int errors = 0;

            // CHECK FOR NULL CASE
            if (firstheader == "" || firstdataheader == "") {
                sendtolog("EMPTY HAPI REQUEST RECEIVED (0)");
                errors = errors + 1;
            }

            // CHECK FOR VALID SETS OF DATA
            if ((firstheader != "" && firstdataheader == "") || (firstheader == "" && firstdataheader != "")) {
                sendtolog("INVALID HAPI REQUEST (1)");
                errors = errors + 1;
            }
            if ((secondheader != "" && seconddataheader == "") || (secondheader == "" && seconddataheader != "")) {
                sendtolog("INVALID HAPI REQUEST (2)");
                errors = errors + 1;
            }
            if ((thirdheader != "" && thirddataheader == "") || (thirdheader == "" && thirddataheader != "")) {
                sendtolog("INVALID HAPI REQUEST (3)");
                errors = errors + 1;
            }
            if ((fourthheader != "" && fourthdataheader == "") || (fourthheader == "" && fourthdataheader != "")) {
                sendtolog("INVALID HAPI REQUEST (4)");
                errors = errors + 1;
            }
            if ((fifthheader != "" && fifthheader == "") || (fifthheader == "" && fifthheader != "")) {
                sendtolog("INVALID HAPI REQUEST (5)");
                errors = errors + 1;
            }

            if (errors == 0) {
                // START PROCESSING HERE
                int runtime = processAPI(clientID, firstheader, firstdataheader, secondheader, seconddataheader, thirdheader, thirddataheader, fourthheader, fourthdataheader, fifthheader, fifthdataheader, "", "", "", "", "", "", "", "");
                return runtime;
            } else {
                // INVALID REQUEST RECEIVED
                return 1;
            }
            sendtolog("FINISHED!");
        }
    } else {
        sendtolog("NULL STRING RECEIVED!");
        return 1;
    }
  return 255;  
}

void apiconnectionthread(int clientID, std::string ipaddress, std::string b11829, std::string c11829) {
    char buffer[4096] = {0};
    std::string clientIDperserver = "ClientID: " + clientID;
    int readrun = read(clientID, buffer, 4096);
    std::string readrunreturn = "Characters Read: " + readrun;
    
    // CHECK FOR ERROR
    if (readrun == -1) {
        logwarning("Client Disconnected Before Reading...", true);
        ip11829[ipaddress] = ip11829[ipaddress] + 10;
    }

    // CONTINUE PROCESSING
    std::string bufferstd = buffer;
    std::string contenttype = "Content: " + bufferstd + "*END-OF-MESSAGE*";

    // SAVE PACKET TO PACKETLOG
    packetlogger("[P11829] - ALLOWED - " + ipaddress + " - " + b11829 + " - " + c11829 + " - " + clientIDperserver + " - " + readrunreturn + " - " + contenttype);

    // ANALYZE COMMANDS
    if (bufferstd.length() >= 50) {
        // READ BUFFER LENGTH HERE
        
        // MAKE SURE THAT IT IS A VALID STRING
        std::string buffertests = bufferstd.substr(0,1);
        std::string realstring;

        // REDO TO FIX HAPI SCRIPT
        if (buffertests == "H") {
            // START READING STATEMENTS
            buffertests = bufferstd.substr(0,4);
            std::string lineanalyze = "";
            bool shiftfound = false;

            // HAPI PROTOCOL
            if (buffertests == "HAPI") {
                lineanalyze = bufferstd.substr(4,4);
                if (lineanalyze == "/1.1") {
                    if (bufferstd.substr(9,22) == "Content-Type:text/json") {
                        std::string messagetoread = bufferstd.substr(33, bufferstd.length() - 33);
                        int result = analyzeAPIandexecute(clientID, messagetoread);
                        if (result != 0) {
                            sendtolog("AN ERROR OCCURRED");
                        }
                    } else {
                        sendtolog("RECEIVED INCOMPATIBLE STRING FROM HAPI");
                    }
                } else {
                    // UNSUPPORTED HAPI VERSION
                    sendtolog("UNSUPPORTED VERSION");
                }
            } else {
                // FAIL
            }
            
        } else {
            
            // SEND ERROR ON API PORT
            int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
        }
    } else {
        // SEND ERROR ON API PORT
        int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
    }

    close(clientID);
}

void handle11829Connections(int server_fd4) {
    bool api11829 = true;
    int apithreadnumber = 0;

    // MARK PORT AS RUNNING ON MEM
    statusP11829.store(1);

    while(api11829 == true) {
        struct sockaddr_in address;
        socklen_t addrlen = sizeof(address);
        int new_socket2;
        ssize_t valread;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);


        int clientID = accept(server_fd4, (struct sockaddr*)&client_addr, &client_addr_len);
        if (clientID < 0) {
            if (clientID == -1) {
                sleep(1);
                if (stopSIGNAL.load() == true) {
                    api11829 = false;
                }
                if (updateSIGNAL.load() == true) {
                    api11829 = false;
                }
            } else {
                loginfo("UNABLE TO ACCEPT API CONNECTION", true);
            }
        } else {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::string ipaddress = client_ip;
            std::string connectionfrom = "Connection from: " + ipaddress;
            std::string clientipstd = client_ip;
            int checks = 0;
            bool allowed = false;

            // PACKETLOGGER
            std::string foundindb;
            std::string statusallow = "Status: ";

            // 11829 SERVER PROTECTION LAYER 1!
            auto searchforip = ip11829.find(clientipstd);
            if (searchforip != ip11829.end()) {
                int logs = searchforip->second;
                foundindb = "Found in DB Previous - Packets: " + logs;
                if (logs >= 6) {
                    statusallow = statusallow + "DENIED!";
                    ip11829.erase(clientipstd);
                    logs = logs + 1;
                    ip11829[clientipstd] = logs;
                } else {
                    allowed = true;
                    ip11829.erase(clientipstd);
                    logs = logs + 1;
                    ip11829[clientipstd] = logs;
                    statusallow = statusallow + "Allowed";
                }
            } else {
                allowed = true;
                ip11829[clientipstd] = 1;
                loginfo("ALLOWED", true);
            }

            // CHECK IF ALLOWED BEFORE ASSIGNING MORE RESOURCES TO IT
            if (allowed == true) {
                loginfo("11829 port initialized", true);
                switch (apithreadnumber) {
                    case 0: {
                        std::thread apithreadnumber00(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber00.detach();
                        break;
                    }
                    case 1: {
                        std::thread apithreadnumber01(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber01.detach();
                        break;
                    }
                    case 2: {
                        std::thread apithreadnumber02(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber02.detach();
                        break;
                    }
                    case 3: {
                        std::thread apithreadnumber03(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber03.detach();
                        break;
                    }
                    case 4: {
                        std::thread apithreadnumber04(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber04.detach();
                        break;
                    }
                    case 5: {
                        std::thread apithreadnumber05(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber05.detach();
                        break;
                    }
                    case 6: {
                        std::thread apithreadnumber06(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber06.detach();
                        break;
                    }
                    case 7: {
                        std::thread apithreadnumber07(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber07.detach();
                        break;
                    }
                    case 8: {
                        std::thread apithreadnumber08(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber08.detach();
                        break;
                    }
                    case 9: {
                        std::thread apithreadnumber09(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber09.detach();
                        break;
                    }
                    case 10: {
                        std::thread apithreadnumber10(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber10.detach();
                        break;
                    }
                    case 11: {
                        std::thread apithreadnumber11(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber11.detach();
                        break;
                    }
                    case 12: {
                        std::thread apithreadnumber12(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber12.detach();
                        break;
                    }
                    case 13: {
                        std::thread apithreadnumber13(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber13.detach();
                        break;
                    }
                    case 14: {
                        std::thread apithreadnumber14(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber14.detach();
                        break;
                    }
                    case 15: {
                        std::thread apithreadnumber15(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber15.detach();
                        break;
                    }
                    case 16: {
                        std::thread apithreadnumber16(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber16.detach();
                        break;
                    }
                    case 17: {
                        std::thread apithreadnumber17(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber17.detach();
                        break;
                    }
                    case 18: {
                        std::thread apithreadnumber18(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber18.detach();
                        break;
                    }
                    case 19: {
                        std::thread apithreadnumber19(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber19.detach();
                        break;
                    }
                    case 20: {
                        std::thread apithreadnumber20(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber20.detach();
                        break;
                    }
                    case 21: {
                        std::thread apithreadnumber21(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber21.detach();
                        break;
                    }
                    case 22: {
                        std::thread apithreadnumber22(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber22.detach();
                        break;
                    }
                    case 23: {
                        std::thread apithreadnumber23(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber23.detach();
                        break;
                    }
                    case 24: {
                        std::thread apithreadnumber24(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber24.detach();
                        break;
                    }
                    case 25: {
                        std::thread apithreadnumber25(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber25.detach();
                        break;
                    }
                    case 26: {
                        std::thread apithreadnumber26(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber26.detach();
                        break;
                    }
                    case 27: {
                        std::thread apithreadnumber27(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber27.detach();
                        break;
                    }
                    case 28: {
                        std::thread apithreadnumber28(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber28.detach();
                        break;
                    }
                    case 29: {
                        std::thread apithreadnumber29(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber29.detach();
                        break;
                    }
                }
                if (apithreadnumber == 29) {
                    apithreadnumber = 0;
                } else {
                    apithreadnumber = apithreadnumber + 1;
                }
                
            } else {
                // SEND ERROR ON API PORT
                int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
                close(clientID);
                packetlogger("[P11829] - BLOCKED - " + connectionfrom + " - " + foundindb + " - " + statusallow);
            }
        }
    }

    // SERVER IS SHUTTING DOWN OR CHANGING
    loginfo("P11829 - Stopped...", true);
    statusP11829.store(0);
    close(server_fd4);
    sleep(1);
    return;
}
