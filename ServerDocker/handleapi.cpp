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
const std::string doublequote = "\"";
const std::string apistartreporting = "{" + doublequote + "STATE" + doublequote + ":" + doublequote + "START_REPORT" + doublequote + "}";



////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (11829) - MAIN API SERVER //
////////////////////////////////////////////////////////////
// PROCESS THE API REQUESTS
int processAPI(int clientID, std::string header1, std::string data1, std::string header2, 
               std::string data2, std::string header3, std::string data3, 
               std::string header4, std::string data4, std::string header5, 
               std::string data5, std::string header6, std::string data6, 
               std::string header7, std::string data7, std::string header8, 
               std::string data8, std::string header9, std::string data9, std::string clientIPADDR) {
    
    // START PROCESSING HERE
    bool completedprocessing = false;
    //std::cout << header1 << ":" << data1 << ":" << header2 << ":" << data2 << std::endl;

    std::cout << "H1=" << header1 << std::endl;
    std::cout << "D1=" << data1 << std::endl;
    std::cout << "H2=" << header2 << std::endl;
    //std::cout << "D2=" << data2 << std::endl;
    //std::cout << "H3=" << header3 << std::endl;
    //std::cout << "D3=" << data3 << std::endl;
    //std::cout << "H4=" << header4 << std::endl;
    //std::cout << "D4=" << data4 << std::endl;
    //std::cout << "H5=" << header5 << std::endl;
    //std::cout << "D5=" << data5 << std::endl;

    // MAIN HEADER RELATING TO HONEYPOT/HONEYPI CONNECTIONS
    if (header1 == "CONNECTION") {
        // MAIN CONNECTION FOR NEW HONEYPIS
        if (data1 == "NEW") {
            // ADD CONDITIONS BASED ON SERVER STATUS AND OTHER THINGS
            // int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
            int updatesig = updateSIGNAL.load();
            int stopsig = stopSIGNAL.load();
            int statusPort = statusP11829.load();
            newConnections.fetch_add(1);

            if (updatesig == 0 && stopsig == 0 && statusPort == 1) {
                send(clientID,apiavailable.c_str(),apiavailable.length(),0);
                analyzedPackets.fetch_add(1);
            } else {
                send(clientID,apiunavailable.c_str(),apiunavailable.length(),0);
                analyzedPackets.fetch_add(1);
                apiRejects.fetch_add(1);
            }
            return 0;
        }

        // ESTABLISH CONNECTION AND VERIFY API KEYS; CREATE NEW TOKEN KEYS
        else if (data1 == "ESTABLISH") {
            if (header2 == "LOGIN" && data2.length() == 68) {
                if (data2.substr(0,4) == "API=") {
                    std::string apiKEY = data2.substr(4,64);
                    std::string newTOKEN;

                    // MAP OPERATIONS
                    // VERSION 2
                    if (apiKEY.length() == 64) {
                        std::map<int, std::string> returnedAUTH = AUTH_checkAPIKey(apiKEY, true);
                        if (returnedAUTH[0] == "1") {
                            // PROCEED TO TEMP AND PUBLISH!
                            // FIX THIS - SAVE NEW TOKEN TO TEMP FILE
                            std::cout << "SUCCESS" << std::endl;
                            newTOKEN = generateRandomStringHoneyPI();
                            storetempapikey(newTOKEN, "");
                        } else {
                            std::cout << "ERROR1:" << returnedAUTH[2] << std::endl;
                            send(clientID,apireject.c_str(),apireject.length(),0);
                            analyzedPackets.fetch_add(1);
                            apiRejects.fetch_add(1);
                        }
                    } else {
                        std::cout << "ERROR2:" << apiKEY.length() << std::endl;
                        send(clientID,apireject.c_str(),apireject.length(),0);
                        analyzedPackets.fetch_add(1);
                        apiRejects.fetch_add(1);
                    }

                    
                    // FIX THIS - ADD PREVIOUS TEMP ONES!
                    /*
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
                        */
                    
                    std::string data3 = "HAPI/1.1 200 OK\nContent-Type:text/json\nContent-Length: 90\n\n{state: success; TOKEN: " + newTOKEN + "}";
                    send(clientID,data3.c_str(),data3.length(),0);
                    analyzedPackets.fetch_add(1);
                    return 0;
                } else {
                    send(clientID,apireject.c_str(),apireject.length(),0);
                    analyzedPackets.fetch_add(1);
                    apiRejects.fetch_add(1);
                }
            } else {
                send(clientID,apireject.c_str(),apireject.length(),0);
                analyzedPackets.fetch_add(1);
                apiRejects.fetch_add(1);
            }
            return 0;
        }

        // CHECK FOR UPDATES SCRIPT
        else if (data1 == "CHECK_FOR_UPDATE") {

        }

        // UPDATE IP LIST AND SEND TO CLIENT
        else if (data1 == "UPDATE") {
            // FUTURE SEND TO CLIENT 
        }

        // REPORT HONEYPOT CONNECTED CORRECTLY TO INTERNET
        else if (data1 == "REPORT") {
            // ADD CONDITIONS BASED ON SERVER STATUS AND OTHER THINGS
            int updatesig = updateSIGNAL.load();
            int stopsig = stopSIGNAL.load();
            int statusPort = statusP11829.load();

            if (updatesig == 0 && stopsig == 0 && statusPort == 1) {
                send(clientID,apiavailable.c_str(),apiavailable.length(),0);
                analyzedPackets.fetch_add(1);
            } else {
                send(clientID,apiunavailable.c_str(),apiunavailable.length(),0);
                analyzedPackets.fetch_add(1);
                apiRejects.fetch_add(1);
            }
            return 0;
        }

        // HONEYPOT SENDING REPORT TO SERVER
        else if (data1 == "NEW_REPORT") {
            // VERIFY DATA
            loginfo("RECEIVED NEW_REPORT REQUEST!", true);
            if (header2 == "TOTALPACKETS") {
                if (statusP11829.load() == 1) {
                    std::cout << "CREATING FILE" << std::endl;
                    if (stringtoint(data2) < 200) {
                        std::string filename = "/home/crashlogs/EN" + ipstring(clientIPADDR) + ".txt";
                        int resultantnumber = access(filename.c_str(), F_OK);
                        int testnumber = 0;
                        bool partitionmax = false;
                        std::string filetotest = "";
                        if (resultantnumber != -1) {
                            while (resultantnumber != -1 && partitionmax == false) {
                                filetotest = "/home/crashlogs/EN" + ipstring(clientIPADDR) + "_" + inttostring(testnumber) + ".txt";
                                resultantnumber = access(filetotest.c_str(), F_OK);
                                testnumber = testnumber + 1;
                                if (testnumber >= 999) {
                                    partitionmax = true;
                                }
                            }
                        } else {
                            filetotest = filename;
                        }
                        
                        
                        // SEND VALID CONDITION
                        if (partitionmax != true && testnumber < 1000) {
                            filetotest = "touch " + filetotest;
                            int results = system(filetotest.c_str());
                            if (results == 0) {
                                loginfo("Valid File at " + inttostring(testnumber), true);
                                send(clientID,apistartreporting.c_str(),apistartreporting.length(),0);
                                analyzedPackets.fetch_add(1);
                                return 0;
                            } else {
                                send(clientID,apireject.c_str(),apireject.length(),0);
                                std::cout << "Could not create file" << std::endl;
                                analyzedPackets.fetch_add(1);
                                apiRejects.fetch_add(1);
                                return 0;
                            }
                        } else {
                            std::cout << "Agreement could not be reached" << std::endl;
                            send(clientID,apireject.c_str(),apireject.length(),0);
                            analyzedPackets.fetch_add(1);
                            apiRejects.fetch_add(1);
                            return 0;
                        }
                    } else {
                        std::cout << "Packet > 200" << std::endl;
                        send(clientID,apireject.c_str(),apireject.length(),0);
                        analyzedPackets.fetch_add(1);
                        apiRejects.fetch_add(1);
                        return 0;
                    }
                } else {
                    send(clientID,apiwaittosend.c_str(),apiwaittosend.length(),0);
                    analyzedPackets.fetch_add(1);
                    return 0;
                }
            } else {
                send(clientID,apireject.c_str(),apireject.length(),0);
                logwarning("Requested New_Report, Yet Lacked Total Packet Header.", true);
                analyzedPackets.fetch_add(1);
                apiRejects.fetch_add(1);
                return 0;
            }
        }

        // HONEYPOT IN MIDDLE OF SENDING LARGE HACKER REPORT
        else if (data1 == "REPORT_PART") {
            loginfo("Reporting part", true);
            
            // PASSTHROUGH ADDRESS INTO FUNCTION TO CREATE FILE AND KEEP IT CONSTANT?
            std::string ipstartname = ipstring(clientIPADDR);
            std::string testcurrentfile = "/home/crashlogs/EN" + ipstartname + ".txt";
            std::string testpastfile = testcurrentfile;
            std::string headerforfile = "/home/crashlogs/EN" + ipstartname + "_";
            int resultant = access(testcurrentfile.c_str(), R_OK);
            int testnumberresult = 0;
            if (resultant == -1) {
                while (resultant == -1) {
                    testcurrentfile = headerforfile + inttostring(testnumberresult) + ".txt";
                    resultant = access(testcurrentfile.c_str(), R_OK);
                    if (resultant == 0) {
                        testpastfile = testcurrentfile;
                    }
                    testnumberresult = testnumberresult + 1;
                }
            } else {
                testpastfile = testcurrentfile;
            }

            std::ofstream encryptfilestreamsave;
            encryptfilestreamsave.open(testpastfile.c_str(), std::ios::app);
            if (encryptfilestreamsave.is_open() == true) {
                if (header3 == "DATA" && data3 != "REPORTFINISH=TRUE") {
                    encryptfilestreamsave << data4;
                    encryptfilestreamsave.close();
                    send(clientID,apisuccess.c_str(),apisuccess.length(),0);
                } else if (header4 == "DATA" && data3 == "REPORTFINISH=TRUE") {
                    encryptfilestreamsave << data5 << std::endl << std::endl;
                    encryptfilestreamsave.close();
                    send(clientID,apisuccess.c_str(),apisuccess.length(),0);
                    std::string commandtomovetofinish = "";
                    std::string movedfilelocation = "";
                    if (testnumberresult == 0) {
                        movedfilelocation = "/home/crashlogs/DOEN" + ipstring(clientIPADDR) + ".txt";
                        commandtomovetofinish = "mv " + testpastfile + " " + movedfilelocation;
                    } else {
                        movedfilelocation = "/home/crashlogs/DOEN" + ipstring(clientIPADDR) + "_" + inttostring(testnumberresult) + ".txt";
                        commandtomovetofinish = "mv " + testpastfile + " " + movedfilelocation;
                    }
                    int sysresult = system(commandtomovetofinish.c_str());
                    if (sysresult == 0) {
                        loginfo("Finished Client COG", true);

                        // LOOPS HERE TO PROCESS THE REPORT AND THEN ADD IT IF NECESSARY
                        std::string ucryptcog = unencryptcog(movedfilelocation, ipstring(clientIPADDR));
                        if (ucryptcog != "" && ucryptcog != "ERROR") {
                            int analyze = processReport(ucryptcog, ipstring(clientIPADDR), false, "");
                            if (analyze != 0) {
                                logcritical("processReport did not Return 0! (" + inttostring(analyze) + ")", true);
                                
                                
                                // IF ANALYZE != 0, THEN 
                                // FIX THIS - ADD MOVE COG TO TEMP SPOT FOR MAN REVIEW


                                conversionErrors.fetch_add(1);
                            }
                            cogsAnalyzed.fetch_add(1);
                        } else {
                            logwarning("Failed to Analyze COG File, leaving in folder for later", true);
                            std::cout << "Ucrypt() error" << std::endl;
                            dataEncryptionErrors.fetch_add(1);
                        }
                        analyzedPackets.fetch_add(1);
                        return 0;
                    } else {
                        logcritical("COULD NOT MOVE FILE TO FINISHED!", true);
                        send(clientID,apireject.c_str(),apireject.length(),0);
                        analyzedPackets.fetch_add(1);
                        apiRejects.fetch_add(1);
                        return 0;
                    }
                } else {
                    std::cout << "INVALID" << std::endl;
                    logcritical("INVALID PACKET RECEIVED IN WRITING REPORT_PART!", true);
                    send(clientID,apireject.c_str(),apireject.length(),0);
                    analyzedPackets.fetch_add(1);
                    apiRejects.fetch_add(1);
                    return 0;
                }
            } else {
                logcritical("UNABLE TO OPEN COG FILE: " + testpastfile, true);
                send(clientID,apireject.c_str(),apireject.length(),0);
                analyzedPackets.fetch_add(1);
                apiRejects.fetch_add(1);
                return 0;
            }
        }
        
        // IF NOTHING MATCHES, ASSUME AN INVALID CONNECTION
        else {
            send(clientID,apireject.c_str(),apireject.length(),0);
            analyzedPackets.fetch_add(1);
            apiRejects.fetch_add(1);
            return 0;
        }
    } else if (header1 == "LOGIN") {
        // DIFFERENT LOGIN METHODS ASSOCIATED HERE
        
    }


    if (completedprocessing == false) {
        invalidPackets.fetch_add(1);
        analyzedPackets.fetch_add(1);
        return 1;
    } else {
        analyzedPackets.fetch_add(1);
        return 0;
    }
    invalidPackets.fetch_add(1);
    analyzedPackets.fetch_add(1);
    return 255;
}

// ANALYZE THE API REQUESTS
int analyzeAPIandexecute(int clientID, std::string messageA, std::string clientIPADDR) {
    loginfo("ANALYZING" + messageA, false);
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
                        loginfo("CURRENT STRING:" + headerlength, true);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing + 1;

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
                                            logcritical("OVERFLOW ERROR IN HAPI PARSER! ", true);
                                            conversionErrors.fetch_add(1);
                                            analyzedPackets.fetch_add(1);
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                        previousmarker = previousmarker + 2;
                    }

                    // ANALYZE DATA HANDLERS TO RESULT
                    if (charactertoanalyze == "\"" && charactertoanalyze2 == ";") {
                        std::string dataheaderlength = message.substr(previousmarker, characteranalyzing - previousmarker);
                        loginfo("CURRENT DATA_STRING" + dataheaderlength, true);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing + 1;

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
                                            logcritical("OVERFLOW ERROR IN HAPI PARSER!", true);
                                            conversionErrors.fetch_add(1);
                                            analyzedPackets.fetch_add(1);
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                        previousmarker = previousmarker + 2;
                    }

                    if (charactertoanalyze == "\"" && charactertoanalyze2 == "}") {
                        std::string dataheaderlength = message.substr(previousmarker, characteranalyzing - previousmarker);
                        loginfo("CURRENT DATA_STRING" + dataheaderlength, true);

                        characteranalyzing = characteranalyzing + 1;
                        previousmarker = characteranalyzing;
                        // + 1

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
                                            logcritical("OVERFLOW ERROR IN HAPI PARSER!", true);
                                            conversionErrors.fetch_add(1);
                                            analyzedPackets.fetch_add(1);
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
                    logcritical("A PARSER ERROR OCCURRED IN HAPI!", true);
                }

                characteranalyzing = characteranalyzing + 1;
            }


            // MAKE SURE DATA IS APPLICABLE AND CORRECT
            int errors = 0;

            // CHECK FOR NULL CASE
            if (firstheader == "" || firstdataheader == "") {
                logwarning("EMPTY HAPI REQUEST RECEIVED (0)", true);
                errors = errors + 1;
            }

            // CHECK FOR VALID SETS OF DATA
            if ((firstheader != "" && firstdataheader == "") || (firstheader == "" && firstdataheader != "")) {
                logwarning("INVALID HAPI REQUEST (1)", true);
                errors = errors + 1;
            }
            if ((secondheader != "" && seconddataheader == "") || (secondheader == "" && seconddataheader != "")) {
                logwarning("INVALID HAPI REQUEST (2)", true);
                errors = errors + 1;
            }
            if ((thirdheader != "" && thirddataheader == "") || (thirdheader == "" && thirddataheader != "")) {
                logwarning("INVALID HAPI REQUEST (3)", true);
                errors = errors + 1;
            }
            if ((fourthheader != "" && fourthdataheader == "") || (fourthheader == "" && fourthdataheader != "")) {
                logwarning("INVALID HAPI REQUEST (4)", true);
                errors = errors + 1;
            }
            if ((fifthheader != "" && fifthheader == "") || (fifthheader == "" && fifthheader != "")) {
                logwarning("INVALID HAPI REQUEST (5)", true);
                errors = errors + 1;
            }

            if (errors == 0) {
                // START PROCESSING HERE
                int runtime = processAPI(clientID, firstheader, firstdataheader, secondheader, seconddataheader, thirdheader, thirddataheader, fourthheader, fourthdataheader, fifthheader, fifthdataheader, "", "", "", "", "", "", "", "", clientIPADDR);
                return runtime;
            } else {
                // INVALID REQUEST RECEIVED
                invalidPackets.fetch_add(1);
                analyzedPackets.fetch_add(1);
                return 1;
            }
            loginfo("FINISHED!", true);
        }
    } else {
        logcritical("NULL STRING RECEIVED!", true);
        invalidPackets.fetch_add(1);
        conversionErrors.fetch_add(1);
        analyzedPackets.fetch_add(1);
        return 1;
    }
    invalidPackets.fetch_add(1);
    analyzedPackets.fetch_add(1);
    return 255;  
}

void apiconnectionthread(int clientID, std::string ipaddress, std::string b11829, std::string c11829) {
    char buffer[4096] = {0};
    std::string clientIDperserver = "ClientID: " + inttostring(clientID);
    int readrun = read(clientID, buffer, 4096);
    std::string readrunreturn = "Characters Read: " + inttostring(readrun);
    
    // CHECK FOR ERROR
    if (readrun == -1) {
        logwarning("Client Disconnected Before Reading...", true);
        ip11829[ipaddress] = ip11829[ipaddress] + 10;
        invalidPackets.fetch_add(1);
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
                        int result = analyzeAPIandexecute(clientID, messagetoread, ipaddress);
                        if (result != 0) {
                            logcritical("AN ERROR OCCURRED (HAPI)", true);
                            std::cout << "RETURNED:" << result << std::endl;
                            invalidPackets.fetch_add(1);
                        }
                        //analyzedPackets.fetch_add(1);
                    } else {
                        logcritical("RECEIVED INCOMPATIBLE STRING FROM HAPI", true);
                        invalidPackets.fetch_add(1);
                        analyzedPackets.fetch_add(1);
                    }
                } else {
                    // UNSUPPORTED HAPI VERSION
                    logcritical("UNSUPPORTED VERSION", true);
                    apiRejects.fetch_add(1);
                    invalidPackets.fetch_add(1);
                    analyzedPackets.fetch_add(1);
                }
            } else {
                // FAIL
                loginfo("Received NOT HAPI Packet on HAPI Interface!", true);
                invalidPackets.fetch_add(1);
                analyzedPackets.fetch_add(1);
            }
            
        } else {
            // SEND ERROR ON API PORT
            send(clientID,apireject.c_str(),apireject.length(),0);
            invalidPackets.fetch_add(1);
            analyzedPackets.fetch_add(1);
        }
    } else {
        // SEND ERROR ON API PORT
        send(clientID,apireject.c_str(),apireject.length(),0);
        invalidPackets.fetch_add(1);
        analyzedPackets.fetch_add(1);
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
                invalidPackets.fetch_add(1);
                analyzedPackets.fetch_add(1);
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
                foundindb = "Found in DB Previous - Packets: " + inttostring(logs);
                if (logs >= 11) {
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
                    case 30: {
                        std::thread apithreadnumber30(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber30.detach();
                        break;
                    }
                    case 31: {
                        std::thread apithreadnumber31(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber31.detach();
                        break;
                    }
                    case 32: {
                        std::thread apithreadnumber32(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber32.detach();
                        break;
                    }
                    case 33: {
                        std::thread apithreadnumber33(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber33.detach();
                        break;
                    }
                    case 34: {
                        std::thread apithreadnumber34(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber34.detach();
                        break;
                    }
                    case 35: {
                        std::thread apithreadnumber35(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber35.detach();
                        break;
                    }
                    case 36: {
                        std::thread apithreadnumber36(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber36.detach();
                        break;
                    }
                    case 37: {
                        std::thread apithreadnumber37(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber37.detach();
                        break;
                    }
                    case 38: {
                        std::thread apithreadnumber38(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber38.detach();
                        break;
                    }
                    case 39: {
                        std::thread apithreadnumber39(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber39.detach();
                        break;
                    }
                    case 40: {
                        std::thread apithreadnumber40(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber40.detach();
                        break;
                    }
                    case 41: {
                        std::thread apithreadnumber41(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber41.detach();
                        break;
                    }
                    case 42: {
                        std::thread apithreadnumber42(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber42.detach();
                        break;
                    }
                    case 43: {
                        std::thread apithreadnumber43(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber43.detach();
                        break;
                    }
                    case 44: {
                        std::thread apithreadnumber44(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber44.detach();
                        break;
                    }
                    case 45: {
                        std::thread apithreadnumber45(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber45.detach();
                        break;
                    }
                    case 46: {
                        std::thread apithreadnumber46(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber46.detach();
                        break;
                    }
                    case 47: {
                        std::thread apithreadnumber47(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber47.detach();
                        break;
                    }
                    case 48: {
                        std::thread apithreadnumber48(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber48.detach();
                        break;
                    }
                    case 49: {
                        std::thread apithreadnumber49(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber49.detach();
                        break;
                    }
                    case 50: {
                        std::thread apithreadnumber50(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber50.detach();
                        break;
                    }
                    case 51: {
                        std::thread apithreadnumber51(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber51.detach();
                        break;
                    }
                    case 52: {
                        std::thread apithreadnumber52(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber52.detach();
                        break;
                    }
                    case 53: {
                        std::thread apithreadnumber53(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber53.detach();
                        break;
                    }
                    case 54: {
                        std::thread apithreadnumber54(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber54.detach();
                        break;
                    }
                    case 55: {
                        std::thread apithreadnumber55(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber55.detach();
                        break;
                    }
                    case 56: {
                        std::thread apithreadnumber56(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber56.detach();
                        break;
                    }
                    case 57: {
                        std::thread apithreadnumber57(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber57.detach();
                        break;
                    }
                    case 58: {
                        std::thread apithreadnumber58(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber58.detach();
                        break;
                    }
                    case 59: {
                        std::thread apithreadnumber59(apiconnectionthread, clientID, ipaddress, foundindb, statusallow);
                        apithreadnumber59.detach();
                        break;
                    }
                }
                if (apithreadnumber == 59) {
                    apithreadnumber = 0;
                } else {
                    apithreadnumber = apithreadnumber + 1;
                }
                
            } else {
                // SEND ERROR ON API PORT
                send(clientID,apireject.c_str(),apireject.length(),0);
                clientsDenied.fetch_add(1);
                analyzedPackets.fetch_add(1);
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
