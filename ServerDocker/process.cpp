#include "process.h"
#include "globalvariables.h"

// MAP VARIABLES
std::map<int, std::string> usercombomap;
std::map<int, std::string> passcombomap;
std::map<int, std::string> commandmap;
std::map<int, std::string> filesmap;
std::map<int, std::string> ipaddrmap;
std::map<int, std::string> extramap;
std::map<int, std::string> filechangesmap;
std::map<int, std::string> fileeditsmap;

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


// "bash"
std::map<std::string, float> commandseveritymap;

// "/home"
std::map<std::string, float> fileaccessseveritymap;

// "ADD uishfes INTO /home/test.txt:1"
std::map<std::string, float> fileeditsseveritymap;

// "/home/test.txt"
std::map<std::string, float> filechangesseveritymap;


//////////////////////////////////////////////
////// DETERMINE SEVERITY OF THE REPORT //////
//////////////////////////////////////////////
int determineseverity(int commandsranonreport, 
                      int filestranonreport, 
                      int ipaddressesonreport, 
                      int extraoptonreport, 
                      int fileschangeonreport, 
                      int fileeditsonreport, 
                      int useronreport, 
                      int passonreport) {
    // DETERMINE SEVERITY

    return -1;
}
    



////////////////////////////////////////////////////////////////
////// PROCESS REPORT FOR THE COMMAND TO WORK (MAIN LOOP) //////
////////////////////////////////////////////////////////////////

// RETURN 10 - FILE STREAM NOT OPENED CORRECTLY
// RETURN 11 - READ/WRITE ERROR
// RETURN 12 - LOGICAL IO ERROR
// RETURN 254 - NOT VALID FILENAME
// RETURN 255 - SHOULD NEVER REACH HERE
int processReport(std::string filename) {

    int linenumber = 0;

    // CHECK FOR VALID PARAMETERS
    if (filename == "") {
        logwarning("Log File NULL: " + filename, true);
        return 254;
        return 254;
    }

    if (filename == "/home/testreport.txt") {
        std::cout << "DEBUG MODE" << std::endl;
    }

    // OPEN INPUT FILE
    std::ifstream reportstream;
    reportstream.open(filename);
    sleep(1);

    if (reportstream.is_open() != 1) {
        logcritical("UNABLE TO OPEN INPUT FILE STREAM: " + filename, false);
        if (reportstream.bad() == true) {
            logcritical("Received Read/Write Error!", true);
            return 11;
            return 11;
        } else if (reportstream.fail() == true) {
            logcritical("Received Logical IO Error!", true);
            return 12;
            return 12;
        } else {
            return 10;
        }
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
    bool fileedits = false;
    char lineraw[2048];

    // INFORMATION OF REPORTS
    int commandsranonreport = 0;
    int filestranonreport = 0;
    int ipaddressesonreport = 0;
    int extraoptonreport = 0;
    int fileschangeonreport = 0;
    int fileeditsonreport = 0;
    int useronreport = 0;
    int passonreport = 0;


    while (completionproc != true || reportstream.eof() != true) {
        reportstream.getline(lineraw, 2048);

        // CONVERT TO STRING FOR ANALYSIS
        std::string linestr = lineraw;
        
        // DEBUG HANDLER
        if (filename == "/home/testreport.txt") {
            std::cout << linenumber << ": " << linestr.length() << ": " << lineraw << std::endl;
            linenumber = linenumber + 1;
        }

        // MAKE SURE IT IS NOT BLANK
        if (linestr.length() > 2) {
            if (usercombo == false && commandprocess == false && files == false && ipaddr == false && extraopt == false && filechanges == false && fileedits == false) {
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
                        if (linestr.substr(0,18) == "commandprocess = {") {
                            commandprocess = true;
                            std::cout << "REACHED HERE" << std::endl;
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
                        if (linestr.substr(0,13) == "usercombo = {") {
                            usercombo = true;
                        }
                    }
                } else if (matchcondition == "fi") {

                    // files - FILES INTERACTED          
                    if (linestr.length() == 9) {
                        if (linestr.substr(0,9) == "files = {") {
                            files = true;
                        }
                    }  

                    // filechanges - FILES INTERACTED          
                    if (linestr.length() == 15) {
                        if (linestr.substr(0,15) == "filechanges = {") {
                            filechanges = true;
                        }
                    }  

                    // fileedits - FILES EDITED          
                    if (linestr.length() == 13) {
                        if (linestr.substr(0,13) == "fileedits = {") {
                            fileedits = true;
                        }
                    }  
                } else if (matchcondition == "ip") {
                    
                    // ipaddr - IP ADDRESSES INTERACTED       
                    if (linestr.length() == 10) {
                        if (linestr.substr(0,10) == "ipaddr = {") {
                            ipaddr = true;
                        }
                    }  
                } else if (matchcondition == "ex") {
                    
                    // extraopt - IP ADDRESSES INTERACTED       
                    if (linestr.length() == 12) {
                        if (linestr.substr(0,12) == "extraopt = {") {
                            extraopt = true;
                        }
                    }  
                } else if (matchcondition == "EN" && linestr.length() == 3) {
                    completionproc = true;
                }
            } else {
                std::cout << "MAPPING" << std::endl;
                if (usercombo == true) {
                    // USERNAME AND PASSWORD STRINGS TO MAP FACE
                    if (linestr.length() >= 8 && linestr.substr(linestr.length() - 1, 1) == ")") {
                        bool userpasscomplete = false;
                        int currentchar = 0;
                        int previousstart = 1;
                        std::string usernameacc = "";
                        std::string passwordacc = "";
                        while (userpasscomplete == false) {
                            if (linestr.length() >= currentchar + 1) {
                                std::string currentstring = linestr.substr(currentchar, 1);
                                if (currentstring == "(") {
                                    // IGNORE
                                } else if (currentstring == ";" && linestr.length() >= currentchar + 5) {
                                    if (linestr.substr(currentchar, 5) == ";[$]:") {
                                        usernameacc = linestr.substr(previousstart, currentchar - previousstart - 1);
                                        previousstart = currentchar + 4;
                                        currentchar = currentchar + 1;
                                    }
                                } else if (currentstring == ")") {
                                    passwordacc = linestr.substr(previousstart, currentchar - previousstart - 1);
                                    userpasscomplete = true;
                                }
                            }
                            currentchar = currentchar + 1;
                        }

                        // LOG TO HEADER
                        if (usernameacc != "" && passwordacc != "") {
                            usercombomap[useronreport] = usernameacc;
                            passcombomap[passonreport] = passwordacc;
                            useronreport = useronreport + 1;
                            passonreport = passonreport + 1;
                        } else {
                            logwarning("Received Invalid Combination of User/Pass - " + linestr, false);
                        }

                    }
                } else if (commandprocess == true) {
                    std::string commandexec = linestr.substr(1, linestr.length() - 2);
                    commandmap.insert({commandsranonreport, commandexec});
                    commandsranonreport = commandsranonreport + 1;
                } else if (files == true) {
                    std::string fileexec = linestr.substr(1, linestr.length());
                    filesmap.insert({filestranonreport, fileexec});
                    filestranonreport = filestranonreport + 1;
                } else if (ipaddr == true) {
                    std::string ipaddr = linestr;
                    ipaddrmap[ipaddressesonreport] = ipaddr;
                    ipaddressesonreport = ipaddressesonreport + 1;
                } else if (extraopt == true) {
                    std::string extraexec = linestr.substr(1, linestr.length() - 2);
                    extramap[extraoptonreport] = extraexec;
                    extraoptonreport = extraoptonreport + 1;
                } else if (filechanges == true) {
                    std::string filechange = linestr.substr(1, linestr.length() - 2);
                    filechangesmap[fileschangeonreport] = filechange;
                    fileschangeonreport = fileschangeonreport + 1;
                } else if (fileedits == true) {
                    std::string fileedits = linestr.substr(1, linestr.length() - 2);
                    fileeditsmap[fileeditsonreport] = fileedits;
                    fileeditsonreport = fileeditsonreport + 1;
                } else {
                    usercombo = false;
                    commandprocess = false;
                    files = false;
                    ipaddr = false;
                    extraopt = false;
                    filechanges = false;
                    fileedits = false;
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
                fileedits = false;
            }
        }
    }


    // PRINT EVERYTHING TO CONSOLE IF DEBUG TEST REPORT IS USED
    if (filename == "/home/testreport.txt") {
        std::cout << "USER" << std::endl;
        for (const auto& pair : usercombomap) {
            std::cout << "#: " << pair.first << ", USER: " << pair.second << std::endl;
        }
        std::cout << "PASS" << std::endl;
        for (const auto& pair : passcombomap) {
            std::cout << "#: " << pair.first << ", PASS: " << pair.second << std::endl;
        }
        std::cout << "COMMAND" << std::endl;
        for (const auto& pair : commandmap) {
            std::cout << "#: " << pair.first << ", CMD: " << pair.second << std::endl;
        }
        std::cout << "FILES" << std::endl;
        for (const auto& pair : filesmap) {
            std::cout << "#: " << pair.first << ", FLS: " << pair.second << std::endl;
        }
        std::cout << "IPADDR" << std::endl;
        for (const auto& pair : ipaddrmap) {
            std::cout << "#: " << pair.first << ", IP: " << pair.second << std::endl;
        }
        std::cout << "EXTRAMAP" << std::endl;
        for (const auto& pair : extramap) {
            std::cout << "#: " << pair.first << ", EXTRA: " << pair.second << std::endl;
        }
        std::cout << "FILES CHANGED" << std::endl;
        for (const auto& pair : filechangesmap) {
            std::cout << "#: " << pair.first << ", FLSCHANGE: " << pair.second << std::endl;
        }
        std::cout << "FILEEDITSMAP" << std::endl;
        for (const auto& pair : fileeditsmap) {
            std::cout << "#: " << pair.first << ", FLSEDIT: " << pair.second << std::endl;
        }
    }
    



// THIS NEXT

    // do something with this
    return 255;
}




///////////////////////////////////////////////////////////
////// CACHE ALL DATABASES FOR SEVERITY MEASUREMENTS //////
////// INTO RAM (UPDATE/RESTORE RAM) //////////////////////
///////////////////////////////////////////////////////////

// "bash"
int cachecommandseverity() {
    
    // OPEN FILE
    std::ifstream commandfile;
    commandfile.open("/home/databases/command_severity.txt");
    if (commandfile.is_open() != 1) {
        logwarning("Unable to open command file!", true);
        return 1;
    }

    char commandloop[2048];

    // READ FROM FILE AND INSERT
    while (commandfile.eof() != true) {
        commandfile.getline(commandloop, 2048);
        std::string commandmapped = commandloop;
        if (commandmapped.length() > 6) {
            std::string severitymeasured = commandmapped.substr(0,4);
            float severitymeasured23 = stringtoint(severitymeasured.substr(0,1)) + (stringtoint(severitymeasured.substr(2,1))/10) + (stringtoint(severitymeasured.substr(3,1))/100);
            std::string restofmessage = commandmapped.substr(6,commandmapped.length() - 6);
            commandseveritymap.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return 2;
        }
    }
    return 0;
}

// "/home"
int cachefileaccess() {
    
    // OPEN FILE
    std::ifstream fileaccess;
    fileaccess.open("/home/databases/file_acces_severity.txt");
    if (fileaccess.is_open() != 1) {
        logwarning("Unable to open access file!", true);
        return 1;
    }

    // VARs
    char accessloop[2048];

    // READ FROM FILE AND INSERT
    while (fileaccess.eof() != true) {
        fileaccess.getline(accessloop, 2048);
        std::string accessmapped = accessloop;
        if (accessmapped.length() > 6) {
            std::string severitymeasured = accessmapped.substr(0,4);
            float severitymeasured23 = stringtoint(severitymeasured.substr(0,1)) + (stringtoint(severitymeasured.substr(2,1))/10) + (stringtoint(severitymeasured.substr(3,1))/100);
            std::string restofmessage = accessmapped.substr(6,accessmapped.length() - 6);
            fileaccessseveritymap.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return 2;
        }
    }
    return 0;
}

// "ADD uishfes INTO /home/test.txt:1"
int cachefileedit() {

    // EDIT FILE
    std::ifstream editfile;
    editfile.open("/home/databases/file_edit_severity.txt");
    if (editfile.is_open() != 1) {
        logwarning("Unable to open EDIT file!", true);
        return 1;
    }

    char editloop[2048];

    // READ FROM FILE AND INSERT
    while (editfile.eof() != true) {
        editfile.getline(editloop, 2048);
        std::string editmapped = editloop;
        if (editmapped.length() > 6) {
            std::string severitymeasured = editmapped.substr(0,4);
            float severitymeasured23 = stringtoint(severitymeasured.substr(0,1)) + (stringtoint(severitymeasured.substr(2,1))/10) + (stringtoint(severitymeasured.substr(3,1))/100);
            std::string restofmessage = editmapped.substr(6,editmapped.length() - 6);
            fileeditsseveritymap.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return 2;
        }
    }
    return 0;
}

// "/home/test.txt"
int cachefilechanges() {

    // EDIT FILE
    std::ifstream changefile;
    changefile.open("/home/databases/file_changes_severity.txt");
    if (changefile.is_open() != 1) {
        logwarning("Unable to open CHANGE file!", true);
        return 1;
    }

    char changeloop[2048];

    // READ FROM FILE AND INSERT
    while (changefile.eof() != true) {
        changefile.getline(changeloop, 2048);
        std::string changemapped = changeloop;
        if (changemapped.length() > 6) {
            std::string severitymeasured = changemapped.substr(0,4);
            float severitymeasured23 = stringtoint(severitymeasured.substr(0,1)) + (stringtoint(severitymeasured.substr(2,1))/10) + (stringtoint(severitymeasured.substr(3,1))/100);
            std::string restofmessage = changemapped.substr(6,changemapped.length() - 6);
            filechangesseveritymap.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return 2;
        }
    }
    return 0;
}


// Main Loop
int cacheseverity() {
    int returnvalues2;
    returnvalues2 = cachecommandseverity();
    returnvalues2 = returnvalues2 + cachefileaccess();
    returnvalues2 = returnvalues2 + cachefileedit();
    returnvalues2 = returnvalues2 + cachefilechanges();
    return returnvalues2;
}


