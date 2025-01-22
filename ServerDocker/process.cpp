#include "process.h"
#include "globalvariables.h"

// MAP VARIABLES
std::map<std::string, std::string> userpasscombo;
std::map<int, std::string> commandmap;

// GENERAL VARIABLES
int reportV = 0;
std::string tokenID = "";
bool testflight = false;
bool testreport = false;
bool partofDDOS = false;
bool complete = false;
bool receiveinvalid = false;

// VERSION VARIABLES
int honeypimainV;
int honeypiminorV;
int honeypihotfixV;
int guestpimainV;
int guestpiminorV;
int guestpihotfixV;

// CALENDAR VARIABLES
int day;
int month;
int year;
int hour;
int minute;
int second;

// METHOD
int method = 0;
// 1 - SSH
// 2 - PORT SCAN

// IP ADDRESS
std::string ipaddress = "";


//////////////////////////////////////////////
////// DETERMINE SEVERITY OF THE REPORT //////
//////////////////////////////////////////////
int determineseverity() {

}


////////////////////////////////////////////////////
////// PROCESS REPORT FOR THE COMMAND TO WORK //////
////////////////////////////////////////////////////

// RETURN 10 - FILE STREAM NOT OPENED CORRECTLY
// RETURN 254 - NOT VALID FILENAME
// RETURN 255 - SHOULD NEVER REACH HERE
int processReport(std::string filename) {

    // CHECK FOR VALID PARAMETERS
    if (filename == "") {
        logwarning("Log File Not Found: ", false);
        sendtolog(filename);
        return 254;
        return 254;
    }

    // OPEN INPUT FILE
    std::ifstream reportstream;
    reportstream.open(filename);
    if (reportstream.is_open() != 0) {
        logcritical("UNABLE TO OPEN INPUT FILE STREAM: ", false);
        sendtolog(filename);
        return 10;
        return 10;
    }

    // MAIN ANALYZING LOOP FOR SCRIPT
    bool completionproc = false;
    bool usercombo = false;
    bool commandprocess = false;
    bool files = false;
    bool ipaddr = false;
    bool extraopt = false;
    bool filechanges = false;
    char lineraw[2048] = "";


    while (completionproc != true || reportstream.eof() != true) {
        reportstream.getline(lineraw, 2048);
        std::string linestr = lineraw;

        // MAKE SURE IT IS NOT BLANK
        if (linestr.length() > 2) {
            if (usercombo == false || commandprocess == false || files == false || ipaddr == false || extraopt == false || filechanges == false) {
                // ANALYZE EACH STRING
                std::string matchcondition = linestr.substr(0,2);
                if (matchcondition == "//") {
                    // IGNORE THIS AND KEEP GOING
                } else if (matchcondition == "re") {

                    // reportV - REPORT MAJOR VERSION
                    if (linestr.length() > 7) {
                        if (linestr.substr(0, 7) == "reportV") {
                            reportV = stringtoint(linestr.substr(linestr.length() - 1, 1));
                        }
                    }
                } else if (matchcondition == "te") {

                    // testflight/testreport - BETA TEST OF REPORT (BETA VERSION)
                    if (linestr.length() > 11) {
                        if (linestr.substr(0,11) == "testflight") {
                            if (linestr.substr(linestr.length() - 4, 4) == "true") {
                                testflight = true;
                            } else if (linestr.substr(linestr.length() - 4, 4) == "alse") {
                                testflight = false;
                            }
                        } else if (linestr.substr(0,11) == "testreport") {
                            if (linestr.substr(linestr.length() - 4, 4) == "true") {
                                testreport = true;
                            } else if (linestr.substr(linestr.length() - 4, 4) == "alse") {
                                testreport = false;
                            }
                        }
                    }
                } else if (matchcondition == "ve") {

                    // VERSION REPORTING FOR THE HONEYPOT!
                    if (linestr.length() >= 17) {
                        if (linestr.substr(0, 16) == "versionreporting") {
                            honeypimainV = stringtoint(linestr.substr(linestr.length() - 5, 1));
                            honeypiminorV = stringtoint(linestr.substr(linestr.length() - 3, 1));
                            honeypihotfixV = stringtoint(linestr.substr(linestr.length() - 1, 1));
                        }
                    }
                } else if (matchcondition == "gu") {

                    // VERSION REPORTING FOR THE GUEST HONEYPOT!
                    if (linestr.length() >= 16) {
                        if (linestr.substr(0, 14) == "guestreporting") {
                            guestpimainV = stringtoint(linestr.substr(linestr.length() - 5, 1));
                            guestpiminorV = stringtoint(linestr.substr(linestr.length() - 3, 1));
                            guestpihotfixV = stringtoint(linestr.substr(linestr.length() - 1, 1));
                        }
                    }
                } else if (matchcondition == "to") {

                    // tokenID - TOKEN ID OF HONEYPOT
                    if (linestr.length() >= 76) {
                        if (linestr.substr(0,7) == "tokenID") {
                            tokenID = linestr.substr(11, 64);
                        }
                    }
                } else if (matchcondition == "da") {

                    // date - DATE OF INCIDENT
                    if (linestr.length() == 17) {
                        if (linestr.substr(0,4) == "date") {
                            day = stringtoint(linestr.substr(11, 2));
                            month = stringtoint(linestr.substr(8, 2));
                            year = stringtoint(linestr.substr(14, 2));
                        }
                    }
                } else if (matchcondition == "ti") {
                    
                    // time - TIME OF INCIDENT
                    if (linestr.length() == 17) {
                        if (linestr.substr(0,4) == "time") {
                            minute = stringtoint(linestr.substr(11, 2));
                            hour = stringtoint(linestr.substr(8, 2));
                            second = stringtoint(linestr.substr(14, 2));
                        }
                    }
                } else if (matchcondition == "me") {

                    // method - WHAT PROTOCOL WAS HACKED?
                    if (linestr.length() > 10) {
                        if (linestr.substr(6,0) == "method") {
                            if (linestr.substr(linestr.length() - 9, 9) == "SSH") {
                                method = 1;
                            } else if (linestr.substr(linestr.length() - 9, 9) == "PORTSCAN") {
                                method = 2;
                            }
                        }
                    }
                } else if (matchcondition == "fr") {

                    // fromIP - IP ADDRESS REPORT IS FROM
                    if (linestr.length() > 9) {
                        if (linestr.substr(6,0) == "fromIP") {
                            ipaddress = linestr.substr(linestr.length() - 10, linestr.length() - 11);
                        }
                    }
                } else if (matchcondition == "pa") {
                    
                    // partofDDOS - Part of DDOS = False
                    if (linestr.length() > 14) {
                        if (linestr.substr(10,0) == "partofDDOS") {
                            if (linestr.substr(linestr.length() - 4, 4) == "true") {
                                partofDDOS = 1;
                            } else if (linestr.substr(linestr.length() - 5, 5) == "false") {
                                partofDDOS = 0;
                            }
                        }
                    }
                } else if (matchcondition == "co") {

                    // complete - MAKE SURE REPORT IS COMPLETE BEFORE CONTINUING
                    if (linestr.length() > 12) {
                        if (linestr.substr(8,0) == "complete") {
                            if (linestr.substr(linestr.length() - 4, 4) == "true") {
                                complete = 1;
                            } else if (linestr.substr(linestr.length() - 5, 5) == "false") {
                                complete = 0;
                            }
                        }
                    }

                    // commandProcess - TERMINAL PROCESS
                    if (linestr.length() == 18) {
                        if (linestr.substr(18,0) == "commandprocess = {") {
                            commandprocess = true;
                        }
                    } 
                } else if (matchcondition == "op") {

                    // option* - OPTION
                    std::string optionnumber = "";
                    if (linestr.length() > 8) {
                        if (linestr.substr(8,1) == " ") {
                            optionnumber = linestr.substr(7,0);
                        } else {
                            optionnumber = linestr.substr(8,0);
                        }
                    }

                    // OPTION PARAMETERS
                    if (optionnumber == "option1") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 1)", true);
                        }
                    } else if (optionnumber == "option2") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 2)", true);
                        }
                    } else if (optionnumber == "option3") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 3)", true);
                        }
                    } else if (optionnumber == "option4") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 4)", true);
                        }
                    } else if (optionnumber == "option5") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 5)", true);
                        }
                    } else if (optionnumber == "option6") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 6)", true);
                        }
                    } else if (optionnumber == "option7") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 7)", true);
                        }
                    } else if (optionnumber == "option8") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 8)", true);
                        }
                    } else if (optionnumber == "option9") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 9)", true);
                        }
                    } else if (optionnumber == "option10") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 10)", true);
                        }
                    } else if (optionnumber == "option11") {
                        if (linestr.substr(linestr.length() - 2, 2) != "NA") {
                            receiveinvalid = true;
                            logwarning("RECEIVED INVALID DURING PARSE OF REPORT! (OPTION 11)", true);
                        }
                    }
                    
                } else if (matchcondition == "us") {
                    
                    // usercombo - PASSWORD BRUTE FORCE
                    if (linestr.length() == 13) {
                        if (linestr.substr(13,0) == "usercombo = {") {
                            usercombo = true;
                        }
                    }
                } else if (matchcondition == "fi") {

                    // files - FILES INTERACTED          
                    if (linestr.length() == 9) {
                        if (linestr.substr(9,0) == "files = {") {
                            files = true;
                        }
                    }  

                    // filechanges - FILES INTERACTED          
                    if (linestr.length() == 15) {
                        if (linestr.substr(15,0) == "filechanges = {") {
                            filechanges = true;
                        }
                    }  
                } else if (matchcondition == "ip") {
                    
                    // ipaddr - IP ADDRESSES INTERACTED       
                    if (linestr.length() == 10) {
                        if (linestr.substr(10,0) == "ipaddr = {") {
                            ipaddr = true;
                        }
                    }  
                } else if (matchcondition == "ex") {
                    
                    // extraopt - IP ADDRESSES INTERACTED       
                    if (linestr.length() == 12) {
                        if (linestr.substr(12,0) == "extraopt = {") {
                            extraopt = true;
                        }
                    }  
                } else if (matchcondition == "EN" && linestr.length() == 3) {
                    completionproc = true;
                }
            } else {
                if (usercombo == true) {
                    // USERNAME AND PASSWORD STRINGS TO MAP FACE
                } else if (commandprocess == true) {
                    std::string commandexec = linestr.substr(1, linestr.length() - 2);
                    // COMMAND TO ADD IT TO THE MAP ABOVE
                } else if (files == true) {
                    std::string fileexec = linestr.substr(1, linestr.length() - 2);
                    // COMMAND TO ADD IT TO MAP HERE
                } else if (ipaddr == true) {
                    std::string ipaddr = linestr;
                    // COMMAND TO MAP
                } else if (extraopt == true) {
                    std::string extraexec = linestr.substr(1, linestr.length() - 2);
                    // COMMAND TO MAP
                } else if (filechanges == true) {
                    // FILE CHANGES

                } else {
                    usercombo = false;
                    commandprocess = false;
                    files = false;
                    ipaddr = false;
                    extraopt = false;
                    filechanges = false;
                }
            }
        } else if (linestr.length() == 1) {
            if (linestr.substr(0,1) == "}") {
                usercombo = false;
                commandprocess = false;
                files = false;
                ipaddr = false;
                extraopt = false;
                filechanges = false;
            }
        }
    }


    // do something with this
    return 255;
}