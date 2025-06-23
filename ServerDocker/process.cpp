#include "process.h"
#include "globalvariables.h"
#include <filesystem>

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
int strictmax = 3;
int severscoremax = 6;
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
// 1 - SSH
// 2 - PORT SCAN
int method = 0;

// IP ADDRESS
std::string ipaddress = "";


// "bash"
//std::map<std::string, float> commandseveritymap;
//std::atomic<std::string> commandseveritymap2;

// "/home"
std::map<std::string, float> fileaccessseveritymap;

// "ADD uishfes INTO /home/test.txt:1"
std::map<std::string, float> fileeditsseveritymap;

// "/home/test.txt"
std::map<std::string, float> filechangesseveritymap;


// FILE LOCATIONS
const std::string usernamelocation = "/home/listfiles/userstream.txt";
const std::string passwordlocation = "/home/listfiles/passstream.txt";
const std::string commandlocation = "/home/listfiles/cmdrun.txt";
const std::string folderlocation = "/home/listfiles/foldacc.txt";
const std::string fileviewlocation = "/home/listfiles/fileacc.txt";
const std::string fileeditslocation = "/home/listfiles/maclist.txt";
const std::string ipliststrictlocation = "/home/listfiles/ipliststrict.txt";
const std::string iplistraw = "/home/listfiles/iplistraw.txt";
const std::string ipliststandardlocation = "/home/listfiles/ipliststandard.txt";
const std::string extraoptfile = "/home/listfiles/extramap.txt";



// SEVERITY OF EACH MAJOR THING!
float userseverity = 0.02;
float passseverity = 0.03;




// IP RAW SEPARATORS
const std::string iprawseparator1 = " [{==}] ";
const std::string iprawseparator2 = " [{__}] ";
const std::string iprawseparator3 = " [{98}] ";
const std::string iprawseparator4 = " [{12}] ";
const std::string iprawseparator5 = " [{..}] ";
const std::string iprawseparator6 = " [{kl}] ";
const std::string iprawseparator7 = " [{tr}] ";
const std::string iprawseparator8 = " [{::}] ";
const std::string iprawseparator9 = " [{**}] ";
const std::string iprawseparator10 = " [{`~}] ";
const std::string iprawseparator11 = " [{()}] ";
const std::string iprawseparator12 = " [{&&}] ";
const std::string iprawseparator13 = " [{%$}] ";
const std::string iprawseparator14 = " [{7/}] ";






//////////////////////////////////////////////////
//// HOLD COG FOR REVIEW LATER AS AUTO FAILED ////
//////////////////////////////////////////////////
// REASON:
//  0 - Failed to Read the COG
//  1 - Failed to Translate the UCrypt
//  2 - Failed to Process the COG Initial
//  3 - Failed to Store a Portion of the COG
//  4 - Failed to Determine Severity
//  5 - Failed to Save IPs To Proper Positions
//  255 - Uncaught Exception

// LINENUMBER:
// (IF APPLICABLE): -1 Otherwise

// CATEGORY:
// (IF APPLICABLE): -1 Otherwise
//  0 - Main Process Report Function
//  1 - Saving Usernames
//  2 - Saving Passwords
//  3 - Saving Commands
//  4 - 

// HOLD COG FOR FURTHER REVIEW LATER
int holdcogforreview(std::string filelocation, std::string newlocation, int reason, int linenumber, int category) {
    if (filelocation == "" || newlocation == "") {
        logwarning("Unable to Move Cog for Review!", true);
        logwarning("A File Location was Deemed NULL", true);
        return -1;
    }

    // OPEN BAD COG
    std::ifstream badcog;
    badcog.open(filelocation.c_str());
    if (badcog.is_open() != true) {
        logwarning("Unable to Open Bad Cog!", true);
        return -2;
    }

    // OPEN NEW OUTPUT FILE
    std::ofstream outputfile;
    outputfile.open(newlocation.c_str());
    if (outputfile.is_open() != true) {
        logwarning("UNABLE TO OPEN Output File for Change COG!", true);
        badcog.close();
        return -3;
    }

    // DECLARE REASON
    outputfile << "HELD BACK FOR REVIEW " << std::endl;

    switch(reason) {
        case 0:
            std::cout << "{REASON:FAILED TO READ COG (0)}" << std::endl;
            break;
        case 1:
            std::cout << "{REASON:Failed to Translate the UCrypt (1)}" << std::endl;
            break;
        case 2:
            std::cout << "{REASON:Failed to Process the Cog Initial (2)}" << std::endl;
            break;
        case 3:
            std::cout << "{REASON:Failed to Store a Portion of the COG (3)}" << std::endl;
            break;
        case 4:
            std::cout << "{REASON:Failed to Determine Severity (4)}" << std::endl;
            break;
        case 5:
            std::cout << "{REASON:Failed to Save IPs to Proper Position (5)}" << std::endl;
            break;
        case 255:
            std::cout << "{REASON:Uncaught Exception (255)}" << std::endl;
            break;
        default:
            std::cout << "{REASON:Uncaught Exception (255)}" << std::endl;  
            break;
    }

    if (category == -1) {
        std::cout << "{CATEGORY: NULL" << std::endl;
    } else {
        std::cout << "{CATEGORY: " << inttostring(category) << "}" << std::endl;
    }

    if (linenumber == -1) {
        std::cout << "{LINE NUMBER: NULL" << std::endl;
    } else {
        std::cout << "{LINE NUMBER: " << inttostring(linenumber) << "}" << std::endl;
    }
    
    outputfile << std::endl << std::endl;


    // READ FROM BADCOG INTO OUTPUTFILE
    std::string readtransfer = "";
    int linenumber23 = 0;
    while (badcog.eof() != true) {
        getline(badcog, readtransfer);
        outputfile << linenumber23 << ":" << readtransfer << std::endl;
        linenumber23 = linenumber23 + 1;
    }
    
    // Close and Return Everything
    badcog.close();
    outputfile.close();
    return 0;
}





/////////////////////////////////
// MOVE COG TO NORMAL POSITION //
/////////////////////////////////
// EXPECTED RESULT
// RETURN = 0;

// UNEXPECTED RESULTS
// RETURN -1 = RECEIVED NULL PARAMETERS
// RETURN -2 = Unable to Open Input
// RETURN -3 = UNABLE TO OPEN OUTPUT
// RETURN -4 = RECEIVED NULL CLIENT IP

int normalfinalizecog(std::string filelocation, std::string cogname, bool systemcall, std::string honeyIP)
{
    if (filelocation == "" || filelocation == "ERROR") {
        logwarning("Finalize Cog Received NULL!", true);
        return -1;
    }

    if (honeyIP == "" || honeyIP == "ERROR") {
        logwarning("Finalize Cog Received NULL Client IP!", true);
        return -4;
    }

    std::ifstream inputcogfile;
    std::ofstream outputfilestream;
    inputcogfile.open(filelocation.c_str());
    if (inputcogfile.is_open() != true) {
        logwarning("Unable to Open Input Cog File (Moving Final)", true);
        return -2;
    }

    std::string outputfilelocation = "/home/crashlogs/finished/" + cogname + ".txt";
    outputfilestream.open(outputfilelocation.c_str());
    if(outputfilestream.is_open() != true) {
        logwarning("UNABLE TO CREATE NEW OUTPUT FILE STREAM (Moving Final)", true);
        return -3;
    }

    outputfilestream << "FINISHED COG FILE" << std::endl;
    time_t currentvalue = time(NULL);
    std::string times = ctime(&currentvalue);
    times = times.substr(0, times.length() - 2);
    outputfilestream << "Finished at: " << times << "UTC time" << std::endl;
    outputfilestream << "HoneyPi Server Version: " << honeyversion << std::endl;
    outputfilestream << "Client IP: " << honeyIP << std::endl;
    outputfilestream << std::endl;
    outputfilestream << "========================" << std::endl;
    outputfilestream << " BEGINNING OF COG BELOW " << std::endl;
    outputfilestream << "========================" << std::endl;
    outputfilestream << std::endl;
    while (inputcogfile.eof() != true) {
        std::string information = "";
        getline(inputcogfile, information);
        outputfilestream << information << std::endl;
    }

    outputfilestream << "=======END OF COG=======" << std::endl;

    std::cout << "RESULTS" << std::endl;
    std::string testcommand = "cat " + outputfilelocation;
    system(testcommand.c_str());

    if (filelocation != "/home/testreport.txt") {
        std::string removecommand = "rm " + filelocation;
        system(removecommand.c_str());
    }

    inputcogfile.close();
    outputfilestream.close();

    return 0;
}





//////////////////////////////////////////////
////// DETERMINE SEVERITY OF THE REPORT //////
//////////////////////////////////////////////
// RETURNS IN THE FORMAT OF (NUMBER, IPADDR, SEVERITY)
// RETURNS (0, ERROR, -1) IN FAILURE
std::map<int, std::map<std::string, float>> determineseverity(std::map<int, std::string> usernames, std::map<int, std::string> passwords, 
                                                            std::map<int, std::string> commands, std::map<int, std::string> foldersviewed, 
                                                            std::map<int, std::string> filesviewed, std::map<int, std::string> fileschanged, 
                                                            std::map<int, std::string> extraopt, std::map<int, std::string> ipaddrs, 
                                                            int extraopt1, int extraopt2, int extraopt3, int extraopt4, int extraopt5, int method) {
    
    // DETERMINE SEVERITY
    int severity = 0;
    std::map<int, std::map<std::string, float>> returnmap;
    std::map<int, std::map<std::string, float>> errormap;
    errormap[0]["ERROR"] = -1;

    int numberofcycles = ipaddrs.size();
    
    // MAP OPERATIONS FOR SEVERITY
    std::map<int, std::map<std::string, float>> severityfeatures;
    severityfeatures = cacheseverity();

    if (severityfeatures[0]["ERROR"] == -1) {
        return errormap;
    } 

    // SAVE SMALLER MAPS FROM LARGER
    std::map<std::string, float> cmdseverity = severityfeatures[0];
    std::map<std::string, float> fldviewed = severityfeatures[1];
    std::map<std::string, float> flchange = severityfeatures[2];
    std::map<std::string, float> flview = severityfeatures[3];

    // GET THE LATEST STATUS VARIABLES
    int currentprocess = 0;

    // MAIN ANALYZING LOOP - CALCULATES SCORES OUT OF 10
    while(currentprocess < numberofcycles) {

        float severityeach = 0;


        // USERNAME ANALYZING
        severityeach = usernames.size() * userseverity;
        

        // PASSWORD ANALYZING
        severityeach = severityeach + passwords.size() * passseverity;


        // COMMAND ANALYZING
        int cmdprev = 0;
        while (cmdprev < commands.size()) {
            if(cmdseverity.find(commands[cmdprev]) != cmdseverity.end()) {
                severityeach = severityeach + cmdseverity[commands[cmdprev]];
            } else {
                severityeach = severityeach + 0.05;
            }
            cmdprev = cmdprev + 1;
        }


        // FOLDER ANALYZING
        int fldma = 0;
        while (fldma < foldersviewed.size()) {
            if(fldviewed.find(foldersviewed[fldma]) != fldviewed.end()) {
                severityeach = severityeach + fldviewed[foldersviewed[fldma]];
            } else {
                severityeach = severityeach + 0.03;
            }
            fldma = fldma + 1;
        }


        // FILE VIEW ANALYZING
        int filvw = 0;
        while (filvw < filesviewed.size()) {
            if(flview.find(filesviewed[filvw]) != flview.end()) {
                severityeach = severityeach + flview[filesviewed[filvw]];
            } else {
                severityeach = severityeach + 0.03;
            }
            filvw = filvw + 1;
        }


        // FILE CHANGE ANALYZING
        int filch = 0;
        while (filch < fileschanged.size()) {
            if(flchange.find(filesviewed[filch]) != flchange.end()) {
                severityeach = severityeach + flchange[fileschanged[filch]];
            } else {
                severityeach = severityeach + 0.06;
            }
            filch = filch + 1;
        }

        
        // IP ADDRS ANALYZING
        int ipaddrnum = 0;
        while (ipaddrnum != ipaddrs.size()) {
            if (ipaddrs[currentprocess] != ipaddrs[ipaddrnum]) {
                std::map<int, std::string> ipaddrinfo = readfromipraw(ipaddrs[ipaddrnum]);
                if (ipaddrinfo[0] != "ERROR" && ipaddrinfo[0] != "NULL") {
                    severityeach = severityeach + (stringtoint(ipaddrinfo[1]) / 10);
                } else {
                    severityeach = severityeach + 0.5;
                }
            }   

            ipaddrnum = ipaddrnum + 1;
        }


        // METHOD ANALYZING
        if (method == 0) {
            severityeach = severityeach + 2;
        } else if (method == 1) {
            if (severityeach < 7) {
                severityeach = severityeach + 1;
            } else {
                severityeach = severityeach + 2;
            }
        } else if (method == 2) {
            if (severityeach < 7) {
                severityeach = severityeach + 1;
            }
        } else {
            severityeach = severityeach + 1;
        }






        // STORE THE FINAL VALUE RECORDED
        returnmap[currentprocess][ipaddrs[currentprocess]] = severityeach;
        currentprocess = currentprocess + 1;
    }

    return returnmap;
}







// FIX THIS - ADD ANALYZING COGS STATUS

//////////////////////////////////////////////////////////
//// SAVE THE VARIOUS PORTIONS OF CRASHLOGS TO FILES! ////
//////////////////////////////////////////////////////////
// SAVE USERNAMES TO THE FILE
int saveusernamestofile(std::map<int, std::string> usernames, bool systemcall) {
    std::fstream usernamefile;
    usernamefile.open(usernamelocation.c_str(), std::ios::in | std::ios::out);
    if (usernamefile.is_open() != true) {
        logwarning("Unable to Open Username File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = usernames.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        usernamefile.seekg(0);
        usernamefile.seekp(0);
        usernamefile.clear();
        //std::cout << current << ":" << usernames[current] << std::endl;
        while (usernamefile.eof() != true && foundbit != true) {
            std::cout << "TRUE" << std::endl;
            std::string getlineofuserfile = "";
            getline(usernamefile, getlineofuserfile);
            if (getlineofuserfile != "") {
                int lastposofcharacter = getlineofuserfile.find_last_of("-");
                int maybe = getlineofuserfile.find(usernames[current]);
                if (lastposofcharacter >= 0) {
                    std::string usertest = getlineofuserfile.substr(0, lastposofcharacter - 1);
                    if (usertest == usernames[current]) {
                        long long int poswriter = usernamefile.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineofuserfile.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        



                        // NEW FIX FOR ISSUE OF CHARACTER TERMINATING
                        std::string possible = usertest + " - " + newnumbertoinsert;
                        if (possible.length() != getlineofuserfile.length()) {
                            std::fstream usernewfix;
                            usernewfix.open(usernamelocation.c_str());
                            if (usernewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            usernamefile.seekg(poswriter);
                            usernewfix.seekp(poswriter - getlineofuserfile.length() - 1);
                            getline(usernamefile, lineA);
                            usernewfix << possible << std::endl;
                            while(usernamefile.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(usernamefile, lineB);
                                    usernewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(usernamefile, lineA);
                                    usernewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                usernamefile << lineA << std::endl;
                            } else {
                                usernamefile << lineB << std::endl;
                            }
                        } else {
                            usernamefile.seekp(poswriter - getlineofuserfile.length() - 1);
                            usernamefile << usertest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream userfileWRITE;
            userfileWRITE.open(usernamelocation.c_str(), std::ios::app);
            if (userfileWRITE.is_open() != true) {
                logwarning("Unable top Open File" , true);
                readwriteoperationfail.fetch_add(1);
                processingErrors.fetch_add(1);
                return -3;
            }

            userfileWRITE << usernames[current] << " - " << newnumbertoinsert << std::endl;
            userfileWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    // DEBUG CALL
    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/userstream.txt";
        system(catread.c_str());
    }

    usernamefile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE PASSWORDS TO THE FILE
int savepasswordstofile(std::map<int, std::string> passwords, bool systemcall) {
    std::fstream passwordfile;
    passwordfile.open(passwordlocation.c_str(), std::ios::in | std::ios::out);
    if (passwordfile.is_open() != true) {
        logwarning("Unable to Open Passwords File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = passwords.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        passwordfile.seekg(0);
        passwordfile.seekp(0);
        passwordfile.clear();
        while (passwordfile.eof() != true && foundbit != true) {
            std::string getlineofpassfile = "";
            getline(passwordfile, getlineofpassfile);
            if (getlineofpassfile != "") {
                int lastposofcharacter = getlineofpassfile.find_last_of("-");
                int maybe = getlineofpassfile.find(passwords[current]);
                if (lastposofcharacter >= 0) {
                    std::string passtest = getlineofpassfile.substr(0, lastposofcharacter - 1);
                    if (passtest == passwords[current]) {
                        long long int poswriter = passwordfile.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineofpassfile.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible2 = passtest + " - " + newnumbertoinsert;



                        if (possible2.length() != getlineofpassfile.length()) {
                            std::fstream passnewfix;
                            passnewfix.open(passwordlocation.c_str());
                            if (passnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            passwordfile.seekg(poswriter);
                            passnewfix.seekp(poswriter - getlineofpassfile.length() - 1);
                            getline(passwordfile, lineA);
                            passnewfix << possible2 << std::endl;
                            while(passwordfile.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(passwordfile, lineB);
                                    passnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(passwordfile, lineA);
                                    passnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                passwordfile << lineA << std::endl;
                            } else {
                                passwordfile << lineB << std::endl;
                            }
                        } else {
                            passwordfile.seekp(poswriter - getlineofpassfile.length() - 1);
                            passwordfile << passtest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream passfileWRITE;
            passfileWRITE.open(passwordlocation.c_str(), std::ios::app);
            if (passfileWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            passfileWRITE << passwords[current] << " - " << newnumbertoinsert << std::endl;
            passfileWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/passstream.txt";
        system(catread.c_str());
    }

    passwordfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE COMMANDS TO THE FILE
int savecommandstofile(std::map<int, std::string> commands, bool systemcall) {
    std::fstream commandfile;
    commandfile.open(commandlocation.c_str(), std::ios::in | std::ios::out);
    if (commandfile.is_open() != true) {
        logwarning("Unable to Open Commands File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = commands.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        commandfile.seekg(0);
        commandfile.seekp(0);
        commandfile.clear();
        while (commandfile.eof() != true && foundbit != true) {
            std::string getlineofcomfile = "";
            getline(commandfile, getlineofcomfile);
            if (getlineofcomfile != "") {
                int lastposofcharacter = getlineofcomfile.find_last_of("-");
                int maybe = getlineofcomfile.find(commands[current]);
                if (lastposofcharacter >= 0) {
                    std::string commandtest = getlineofcomfile.substr(0, lastposofcharacter - 1);
                    if (commandtest == commands[current]) {
                        long long int poswriter = commandfile.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineofcomfile.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible3 = commandtest + " - " + newnumbertoinsert;

                        
                        
                        if (possible3.length() != getlineofcomfile.length()) {
                            std::fstream commnewfix;
                            commnewfix.open(commandlocation.c_str());
                            if (commnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            commandfile.seekg(poswriter);
                            commnewfix.seekp(poswriter - getlineofcomfile.length() - 1);
                            getline(commandfile, lineA);
                            commnewfix << possible3 << std::endl;
                            while(commandfile.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(commandfile, lineB);
                                    commnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(commandfile, lineA);
                                    commnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                commandfile << lineA << std::endl;
                            } else {
                                commandfile << lineB << std::endl;
                            }
                        } else {
                            commandfile.seekp(poswriter - getlineofcomfile.length() - 1);
                            commandfile << commandtest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream commandfileWRITE;
            commandfileWRITE.open(commandlocation.c_str(), std::ios::app);
            if (commandfileWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            commandfileWRITE << commands[current] << " - " << newnumbertoinsert << std::endl;
            commandfileWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/cmdrun.txt";
        system(catread.c_str());
    }

    commandfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE FOLDERS ACCESSED TO FILE
int savefoldertofile(std::map<int, std::string> folders, bool systemcall) {
    std::fstream folderfile;
    folderfile.open(folderlocation.c_str(), std::ios::in | std::ios::out);
    if (folderfile.is_open() != true) {
        logwarning("Unable to Open Folder File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = folders.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        folderfile.seekg(0);
        folderfile.seekp(0);
        folderfile.clear();
        while (folderfile.eof() != true && foundbit != true) {
            std::string getlineoffolderfile = "";
            getline(folderfile, getlineoffolderfile);
            if (getlineoffolderfile != "") {
                int lastposofcharacter = getlineoffolderfile.find_last_of("-");
                int maybe = getlineoffolderfile.find(folders[current]);
                if (lastposofcharacter >= 0) {
                    std::string foldertest = getlineoffolderfile.substr(0, lastposofcharacter - 1);
                    if (foldertest == folders[current]) {
                        long long int poswriter = folderfile.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineoffolderfile.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible4 = foldertest + " - " + newnumbertoinsert;

                        
                        
                        if (possible4.length() != getlineoffolderfile.length()) {
                            std::fstream foldnewfix;
                            foldnewfix.open(folderlocation.c_str());
                            if (foldnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            folderfile.seekg(poswriter);
                            foldnewfix.seekp(poswriter - getlineoffolderfile.length() - 1);
                            getline(folderfile, lineA);
                            foldnewfix << possible4 << std::endl;
                            while(folderfile.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(folderfile, lineB);
                                    foldnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(folderfile, lineA);
                                    foldnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                folderfile << lineA << std::endl;
                            } else {
                                folderfile << lineB << std::endl;
                            }
                        } else {
                            folderfile.seekp(poswriter - getlineoffolderfile.length() - 1);
                            folderfile << foldertest << " - " << newnumbertoinsert << std::endl;
                        }


                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream folderfileWRITE;
            folderfileWRITE.open(folderlocation.c_str(), std::ios::app);
            if (folderfileWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            folderfileWRITE << folders[current] << " - " << newnumbertoinsert << std::endl;
            folderfileWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/foldacc.txt";
        system(catread.c_str());
    }

    folderfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE FILE VIEWED TO FILE
int savefilesviewedtofile(std::map<int, std::string> filechanges, bool systemcall) {
    std::fstream viewedfile;
    viewedfile.open(fileviewlocation.c_str(), std::ios::in | std::ios::out);
    if (viewedfile.is_open() != true) {
        logwarning("Unable to Open Files Viewed File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = filechanges.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        viewedfile.seekg(0);
        viewedfile.seekp(0);
        viewedfile.clear();
        while (viewedfile.eof() != true && foundbit != true) {
            std::string getlineofviewfile = "";
            getline(viewedfile, getlineofviewfile);
            if (getlineofviewfile != "") {
                int lastposofcharacter = getlineofviewfile.find_last_of("-");
                int maybe = getlineofviewfile.find(filechanges[current]);
                if (lastposofcharacter >= 0) {
                    std::string viewtest = getlineofviewfile.substr(0, lastposofcharacter - 1);
                    if (viewtest == filechanges[current]) {
                        long long int poswriter = viewedfile.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineofviewfile.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible5 = viewtest + " - " + newnumbertoinsert;

                        
                        
                        if (possible5.length() != getlineofviewfile.length()) {
                            std::fstream viewnewfix;
                            viewnewfix.open(fileviewlocation.c_str());
                            if (viewnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            viewedfile.seekg(poswriter);
                            viewnewfix.seekp(poswriter - getlineofviewfile.length() - 1);
                            getline(viewedfile, lineA);
                            viewnewfix << possible5 << std::endl;
                            while(viewedfile.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(viewedfile, lineB);
                                    viewnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(viewedfile, lineA);
                                    viewnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                viewedfile << lineA << std::endl;
                            } else {
                                viewedfile << lineB << std::endl;
                            }
                        } else {
                            viewedfile.seekp(poswriter - getlineofviewfile.length() - 1);
                            viewedfile << viewtest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream viewfileWRITE;
            viewfileWRITE.open(fileviewlocation.c_str(), std::ios::app);
            if (viewfileWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            viewfileWRITE << filechanges[current] << " - " << newnumbertoinsert << std::endl;
            viewfileWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/fileacc.txt";
        system(catread.c_str());
    }

    viewedfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE THE CHANGES TO FILES TO FILE STREAM
int savefileeffectstofile(std::map<int, std::string> fileeffects, bool systemcall) {
    std::fstream fileedits;
    fileedits.open(fileeditslocation.c_str(), std::ios::in | std::ios::out);
    if (fileedits.is_open() != true) {
        logwarning("Unable to Open File Edits!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = fileeffects.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        fileedits.seekg(0);
        fileedits.seekp(0);
        fileedits.clear();
        while (fileedits.eof() != true && foundbit != true) {
            std::string getlineoffileedits = "";
            getline(fileedits, getlineoffileedits);
            if (getlineoffileedits != "") {
                int lastposofcharacter = getlineoffileedits.find_last_of("-");
                int maybe = getlineoffileedits.find(fileeffects[current]);
                if (lastposofcharacter >= 0) {
                    std::string fileedittest = getlineoffileedits.substr(0, lastposofcharacter - 1);
                    if (fileedittest == fileeffects[current]) {
                        long long int poswriter = fileedits.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineoffileedits.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible6 = fileedittest + " - " + newnumbertoinsert;

                        
                        
                        if (possible6.length() != getlineoffileedits.length()) {
                            std::fstream effectnewfix;
                            effectnewfix.open(fileeditslocation.c_str());
                            if (effectnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            fileedits.seekg(poswriter);
                            effectnewfix.seekp(poswriter - getlineoffileedits.length() - 1);
                            getline(fileedits, lineA);
                            effectnewfix << possible6 << std::endl;
                            while(fileedits.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(fileedits, lineB);
                                    effectnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(fileedits, lineA);
                                    effectnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                fileedits << lineA << std::endl;
                            } else {
                                fileedits << lineB << std::endl;
                            }
                        } else {
                            fileedits.seekp(poswriter - getlineoffileedits.length() - 1);
                            fileedits << fileedittest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream fileeditsWRITE;
            fileeditsWRITE.open(fileeditslocation.c_str(), std::ios::app);
            if (fileeditsWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            fileeditsWRITE << fileeffects[current] << " - " << newnumbertoinsert << std::endl;
            fileeditsWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/maclist.txt";
        system(catread.c_str());
    }

    fileedits.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// SAVE IP ADDR TO VARIOUS FILES
int saveipaddrPREMIUMFILE(std::map<int, std::string> ipaddrs, std::map<int, std::map<std::string, float>> severity, bool systemcall) {
    int ipstosave = ipaddrs.size();
    int currently = 0;
    bool errormap = false;
    while (currently < ipstosave) {
        std::string ipaddr = ipaddrs[currently];
        int severitynumber = severity[currently][ipaddr];
        if (severitynumber > 0) {
            std::map<int, float> returnedvalues = saveiptoTIMEBASEDFILE(ipaddr, severitynumber, true, 1);

            // STRICT
            if (returnedvalues[0] < 0.2) {
                std::cout << "SAVING TO STRICT!" << std::endl;
                logwarning("ERROR OCCURRED IN IP LOG FUNCTION!", true);
                saveiptoSTRICTFILE(ipaddrs[currently], true);
                errormap = true;
            } else {
                if (returnedvalues[0] > strictmax || returnedvalues[1] > severscoremax) {
                    saveiptoSTRICTFILE(ipaddrs[currently], true);
                }
            }

            // STANDARD
            if (returnedvalues[1] < 0.2) {
                logwarning("ERROR OCCURRED IN IP LOG FUNCTION (2)!", true);
                saveiptoSTRICTFILE(ipaddrs[currently], true);
                errormap = true;
            } else {
                if (returnedvalues[1] > severscoremax) {
                    saveiptoSTANDARDFILE(ipaddrs[currently], true);
                }
            }
        } else {
            logwarning("Severity Returned <= 0!", true);
            return -1;
        }

        currently = currently + 1;
    }

    // ADD TO MORE INFO
    // ADD TO EXTRA INFO
    

    return currently;
}


// ADD IPADDR TO STANDARD SECURITY FILE
// STANDARD GOES OFF OF SCORES
int saveiptoSTANDARDFILE(std::string ipaddr, bool systemcall) {
    if (ipaddr == "") {
        logwarning("NULL Condition Received (IP STANDARD)", true);
        return -1;
    }

    std::fstream standfile;
    standfile.open(ipliststandardlocation.c_str());
    if (standfile.is_open() != true) {
        logwarning("UNABLE TO OPEN IP STANDARD (WRITE)", true);
        return -2;
    }

    int remarkable = 0;
    std::string linefromfile = "";
    while (remarkable < 1000 && standfile.eof() != true) {
        getline(standfile, linefromfile);
        if (linefromfile == ipaddr) {
            return 0;
        }
        remarkable = remarkable + 1;
    }

    if (standfile.eof() == true) {
        std::fstream ipstream;
        ipstream.open(ipliststandardlocation.c_str(), std::ios::app);
        if (ipstream.is_open() != true) {
            logwarning("UNABLE TO OPEN IP STANDARD (WRITE-2)", true);
            return -4;
        }

        ipstream << ipaddr << std::endl;
        return 1;
    }
    return -3;
}


// ADD IPADDR TO STRICT SECURITY FILE
// STRICT GOES STRICTLY OFF OF NUMBER OF TIMES
int saveiptoSTRICTFILE(std::string ipaddr, bool systemcall) {
    if (ipaddr == "") {
        logwarning("NULL Condition Received (IP STRICT)", true);
        return -1;
    }

    std::fstream strictfile;
    strictfile.open(ipliststrictlocation.c_str());
    if (strictfile.is_open() != true) {
        logwarning("UNABLE TO OPEN IP STRICT (WRITE)", true);
        return -2;
    }

    int remarkable = 0;
    std::string linefromfile = "";
    while (remarkable < 1000 && strictfile.eof() != true) {
        getline(strictfile, linefromfile);
        if (linefromfile == ipaddr) {
            return 0;
        }
        remarkable = remarkable + 1;
    }

    if (strictfile.eof() == true) {
        std::fstream ipstream;
        ipstream.open(ipliststrictlocation.c_str(), std::ios::app);
        if (ipstream.is_open() != true) {
            logwarning("UNABLE TO OPEN IP STRICT (WRITE-2)", true);
            return -4;
        }

        ipstream << ipaddr << std::endl;
        return 1;
    }
    return -3;
}


// ADD IPADDR TO TIMEBASED (RAW) FILE
// RETURNS SCORE OF IP
// 0 => NumberOfTimes (STRICT)
// 1 => TotalScore (STANDARD)
std::map<int, float> saveiptoTIMEBASEDFILE(std::string ipaddr, float severity, bool systemcall, int packets) {
    std::map<int, float> returnvalues;
    returnvalues[0] = -1;
    returnvalues[1] = -1;

    // CHECK FOR NULL CONDITIONS
    if (ipaddr == "") {
        logwarning("Save to Raw Returned with a NULL IP Address!", true);
        return returnvalues;
    }
    if (severity < 0.5) {
        logwarning("Severity Returned Too Low", true);
        severity = 7.5;
    }

    // CHECK FOR PREVIOUS CONDITION
    std::map<int, std::string> readvalues;
    readvalues = readfromipraw(ipaddr);

    if (packets == -1) {
        severity = stringtofloat(readvalues[7]);
    }



    // CASE 1 - FUNCTION RETURNS AN ERROR
    if (readvalues[0] == "ERROR") {
        return returnvalues;
    }



    // CASE 2 - FUNCTION RETURNS IP NOT ALREADY IN FILE
    if (readvalues[0] == "NULL") {
        std::fstream iplistrawfile;
        iplistrawfile.open(iplistraw.c_str(), std::ios::app);
        if (iplistrawfile.is_open() != true) {
            logwarning("UNABLE TO OPEN IP LIST RAW FILE TO WRITE STD::IOS::APP", true);
            return returnvalues;
        }

        iplistrawfile << ipaddr << iprawseparator1 << severity << iprawseparator2 << static_cast<long int> (time(NULL)) << iprawseparator3 << static_cast<long int> (time(NULL)) << iprawseparator4 << "1" << iprawseparator5 << severity << iprawseparator6 << severity << iprawseparator7 << severity << iprawseparator8 << "N" << iprawseparator9 << "N" << iprawseparator10 << "N" << iprawseparator11 << "N" << iprawseparator12 << "1" << iprawseparator13 << "0" << iprawseparator14 << "N" << std::endl;
        returnvalues[0] = 1;
        returnvalues[1] = severity;

        return returnvalues;
    }



    // CASE 3 - FUNCTION RETURNS VALID IP ALREADY MARKED
    if (readvalues[0] != ipaddr && stringtoint(readvalues[100]) > 25) {
        return returnvalues;
    }
    std::string returnedIPADDR = readvalues[0];
    std::string runningseverityOLD = readvalues[1];
    float runningseverityNEW = stringtofloat(runningseverityOLD);

    
    runningseverityNEW = (((runningseverityNEW - (runningseverityNEW/30)) * 30) + severity)/30;
    
    
    
    std::string firstpacketnew = readvalues[3];
    
    
    int numberofpackets = stringtoint(readvalues[4]);
    if (packets == 1) {
        numberofpackets = numberofpackets + 1;
    } else if (packets == -1) {
        numberofpackets = numberofpackets - 1;

    } else {
        logwarning("NUM NOT SET CORRECTLY (SAVING)", true);
        return returnvalues;
    }
    std::string numberofpacketsNEW = inttostring(numberofpackets);
    
    
    std::string maxsevereNEW = "";
    if (stringtoint(readvalues[5]) > severity) {
        maxsevereNEW = readvalues[5];
    } else {
        maxsevereNEW = inttostring(severity);
    }
    std::cout << "|" << maxsevereNEW << "|" << std::endl;

    
    std::string minsevereNEW = "";
    if (stringtoint(readvalues[6]) < severity) {
        minsevereNEW = readvalues[6];
    } else {
        minsevereNEW = inttostring(severity);
    }

    std::string newinputtomean = readvalues[7];
    std::string meanNEW = inttostring(((stringtoint(newinputtomean) * (numberofpackets - 1)) + severity) / numberofpackets);

    
    std::string devBanNEW = readvalues[8];
    std::string permbanNEW = readvalues[9];
    std::string liftbanNEW = readvalues[10];
    std::string associateNEW = readvalues[11];
    std::string numberpacketsNEW = inttostring(stringtoint(readvalues[12]) + 1);
    std::string dayssinceLastNEW = "0";
    std::string notesNew = readvalues[14];


    int posInFile = stringtoint(readvalues[100]);
    int lengthofString = stringtoint(readvalues[101]);


    std::fstream ipallinfo;
    ipallinfo.open(iplistraw.c_str());


    if (ipallinfo.is_open() != true) {
        returnvalues[0] = -1;
        returnvalues[1] = -1;
        return returnvalues;
    }

    long int legendary = static_cast<long int> (time(NULL));
    std::string newstring = returnedIPADDR + iprawseparator1 + inttostring(runningseverityNEW) + iprawseparator2 + std::to_string(legendary) + iprawseparator3 + firstpacketnew + iprawseparator4 + numberofpacketsNEW + iprawseparator5 + maxsevereNEW + iprawseparator6 + minsevereNEW + iprawseparator7 + meanNEW + iprawseparator8 + devBanNEW + iprawseparator9 + permbanNEW + iprawseparator10 + liftbanNEW + iprawseparator11 + associateNEW + iprawseparator12 + numberofpacketsNEW + iprawseparator13 + dayssinceLastNEW + iprawseparator14 + notesNew;
    std::cout << legendary << " - RECEIVED FROM FUNC: " << std::to_string(legendary) << "{}" << newstring << std::endl;
    if (newstring.length() != lengthofString) {
        std::fstream iprawfix;
        iprawfix.open(iplistraw.c_str());
        if (iprawfix.is_open() != true) {
            returnvalues[0] = -1;
            returnvalues[1] = -1;
            return returnvalues;
        }
        std::string lineA = "";
        std::string lineB = "";
        bool switchAB = false;
        // false = A; true = B;
        ipallinfo.seekg(posInFile);
        iprawfix.seekp(posInFile - lengthofString - 1);
        getline(ipallinfo, lineA);
        iprawfix << newstring << std::endl;
        while(ipallinfo.eof() != true) {
            if (switchAB == false) {
                switchAB = true;
                getline(ipallinfo, lineB);
                iprawfix << lineA << std::endl;
            } else {
                switchAB = false;
                getline(ipallinfo, lineA);
                iprawfix << lineB << std::endl;
            }
        }
        if (switchAB == false) {
            ipallinfo << lineA << std::endl;
        } else {
            ipallinfo << lineB << std::endl;
        }
    } else {
        ipallinfo.seekp(posInFile - lengthofString - 1);
        ipallinfo << newstring << std::endl;        
    }



    returnvalues[0] = numberofpackets;
    returnvalues[1] = runningseverityNEW;


    ipallinfo.close();
    return returnvalues;
}






// ADD IPADDR TO IP MORE INFO FILE 
int saveiptoMOREINFOFILE(std::string ipaddr, int method, bool systemcall) {
    // FIX THIS



    return -1;
}


// ADD IPADDR TO PERMANENT IP FILE
int saveiptoPERMANENTFILE(std::string, int severity, bool systemcall) {
    // FIX THIS





    return -1;
}


// RECEIVED ON EXTRA OPT IN SEPARTE FILE
// NOTHING FOR NOW CAUSE EXTRA NOT NEEDED YET!
int saveextraopttofile(std::map<int, std::string> extraopt, bool systemcall) {
    std::fstream extrastream;
    extrastream.open(extraoptfile.c_str(), std::ios::in | std::ios::out);
    if (extrastream.is_open() != true) {
        logwarning("Unable to Open EXTRA OPT FILE!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = extraopt.size();
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        extrastream.seekg(0);
        extrastream.seekp(0);
        extrastream.clear();
        while (extrastream.eof() != true && foundbit != true) {
            std::string getlineofextraopt = "";
            getline(extrastream, getlineofextraopt);
            if (getlineofextraopt != "") {
                int lastposofcharacter = getlineofextraopt.find_last_of("-");
                int maybe = getlineofextraopt.find(extraopt[current]);
                if (lastposofcharacter >= 0) {
                    std::string extraopttest = getlineofextraopt.substr(0, lastposofcharacter - 1);
                    if (extraopttest == extraopt[current]) {
                        long long int poswriter = extrastream.tellg();
                        foundbit = true;
                        std::string numberoftimes = getlineofextraopt.substr(lastposofcharacter + 2);
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        std::string possible6 = extraopttest + " - " + newnumbertoinsert;

                        
                        
                        if (possible6.length() != getlineofextraopt.length()) {
                            std::fstream effectnewfix;
                            effectnewfix.open(extraoptfile.c_str());
                            if (effectnewfix.is_open() != true) {
                                return -1;
                            }
                            std::string lineA = "";
                            std::string lineB = "";
                            bool switchAB = false;
                            // false = A; true = B;
                            extrastream.seekg(poswriter);
                            effectnewfix.seekp(poswriter - getlineofextraopt.length() - 1);
                            getline(extrastream, lineA);
                            effectnewfix << possible6 << std::endl;
                            while(extrastream.eof() != true) {
                                if (switchAB == false) {
                                    switchAB = true;
                                    getline(extrastream, lineB);
                                    effectnewfix << lineA << std::endl;
                                } else {
                                    switchAB = false;
                                    getline(extrastream, lineA);
                                    effectnewfix << lineB << std::endl;
                                }
                            }
                            if (switchAB == false) {
                                extrastream << lineA << std::endl;
                            } else {
                                extrastream << lineB << std::endl;
                            }
                        } else {
                            extrastream.seekp(poswriter - getlineofextraopt.length() - 1);
                            extrastream << extraopttest << " - " << newnumbertoinsert << std::endl;
                        }



                        saved = saved + 1;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::string newnumbertoinsert = "1";
            std::ofstream extraoptWRITE;
            extraoptWRITE.open(extraoptfile.c_str(), std::ios::app);
            if (extraoptWRITE.is_open() != true) {
                logwarning("Unable top Open File", true);
                processingErrors.fetch_add(1);
                readwriteoperationfail.fetch_add(1);
                return -3;
            }

            extraoptWRITE << extraopt[current] << " - " << newnumbertoinsert << std::endl;
            extraoptWRITE.close();
            saved = saved + 1;
        }

        current = current + 1;
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/extramap.txt";
        system(catread.c_str());
    }

    extrastream.close();

    entryAdded.fetch_add(saved);

    return saved;
}



// ADD IP THAT THE DEV HAS PERMANENTLY BLOCKED FROM REACHING HIS SERVERS
int devblockipaddrtofiles(std::string ipaddr, bool systemcall) {
    // FIX THIS
    std::map<int, std::string> mapsofreturned;
    mapsofreturned = readfromipraw(ipaddr);

    




    return -1;
}







///////////////////////////////////////////
//// REMOVE NUMBER IF NEEDED FROM FILE ////
///////////////////////////////////////////
// REMOVE USERNAME FROM FILE
int removeusernamefromfile(std::string username, bool systemcall) {
    std::fstream usernamefile;
    usernamefile.open(usernamelocation.c_str(), std::ios::in | std::ios::out);
    if (usernamefile.is_open() != true) {
        logwarning("Unable to Open Username File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (usernamefile.eof() != true && foundbit != true) {
            std::string getlineofuserfile = "";
            getline(usernamefile, getlineofuserfile);
            if (getlineofuserfile != "") {
                int lastposofcharacter = getlineofuserfile.find_last_of("-");
                int maybe = getlineofuserfile.find(username);
                if (lastposofcharacter >= 0) {
                    std::string usertest = getlineofuserfile.substr(0, lastposofcharacter - 1);
                    if (usertest == username) {
                        long long int poswriter = usernamefile.tellg();
                        std::string numberoftimes = getlineofuserfile.substr(lastposofcharacter + 2);

                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            usernamefile.seekp(poswriter - getlineofuserfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineofuserfile.length()) {
                                usernamefile << " ";
                                charnumber = charnumber + 1;
                            }
                            usernamefile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            usernamefile.seekp(poswriter - getlineofuserfile.length() - 1);
                            usernamefile << usertest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/userstream.txt";
        system(catread.c_str());
    }

    usernamefile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// REMOVE PASSWORD FROM FILE
int removepasswordfromfile(std::string password, bool systemcall) {
    std::fstream passwordfile;
    passwordfile.open(passwordlocation.c_str(), std::ios::in | std::ios::out);
    if (passwordfile.is_open() != true) {
        logwarning("Unable to Open Password File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (passwordfile.eof() != true && foundbit != true) {
            std::string getlineofpassfile = "";
            getline(passwordfile, getlineofpassfile);
            if (getlineofpassfile != "") {
                int lastposofcharacter = getlineofpassfile.find_last_of("-");
                int maybe = getlineofpassfile.find(password);
                if (lastposofcharacter >= 0) {
                    std::string passtest = getlineofpassfile.substr(0, lastposofcharacter - 1);
                    if (passtest == password) {
                        long long int poswriter = passwordfile.tellg();
                        std::string numberoftimes = getlineofpassfile.substr(lastposofcharacter + 2);
                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            passwordfile.seekp(poswriter - getlineofpassfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineofpassfile.length()) {
                                passwordfile << " ";
                                charnumber = charnumber + 1;
                            }
                            passwordfile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            passwordfile.seekp(poswriter - getlineofpassfile.length() - 1);
                            passwordfile << passtest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/passstream.txt";
        system(catread.c_str());        
    }

    passwordfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// REMOVE COMMAND FROM FILE
int removecommandfromfile(std::string command, bool systemcall) {
    std::fstream commandfile;
    commandfile.open(commandlocation.c_str(), std::ios::in | std::ios::out);
    if (commandfile.is_open() != true) {
        logwarning("Unable to Open Command File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (commandfile.eof() != true && foundbit != true) {
            std::string getlineofcommfile = "";
            getline(commandfile, getlineofcommfile);
            if (getlineofcommfile != "") {
                int lastposofcharacter = getlineofcommfile.find_last_of("-");
                int maybe = getlineofcommfile.find(command);
                if (lastposofcharacter >= 0) {
                    std::string commtest = getlineofcommfile.substr(0, lastposofcharacter - 1);
                    if (commtest == command) {
                        long long int poswriter = commandfile.tellg();
                        std::string numberoftimes = getlineofcommfile.substr(lastposofcharacter + 2);
                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            commandfile.seekp(poswriter - getlineofcommfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineofcommfile.length()) {
                                commandfile << " ";
                                charnumber = charnumber + 1;
                            }
                            commandfile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            commandfile.seekp(poswriter - getlineofcommfile.length() - 1);
                            commandfile << commtest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/cmdrun.txt";
        system(catread.c_str());
    }

    commandfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// REMOVE FOLDERS ACCESSED FROM FILE
int removefolderfromfile(std::string folder, bool systemcall) {
    std::fstream folderfile;
    folderfile.open(folderlocation.c_str(), std::ios::in | std::ios::out);
    if (folderfile.is_open() != true) {
        logwarning("Unable to Open Folders File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (folderfile.eof() != true && foundbit != true) {
            std::string getlineoffoldfile = "";
            getline(folderfile, getlineoffoldfile);
            if (getlineoffoldfile != "") {
                int lastposofcharacter = getlineoffoldfile.find_last_of("-");
                int maybe = getlineoffoldfile.find(folder);
                if (lastposofcharacter >= 0) {
                    std::string foldtest = getlineoffoldfile.substr(0, lastposofcharacter - 1);
                    if (foldtest == folder) {
                        long long int poswriter = folderfile.tellg();
                        std::string numberoftimes = getlineoffoldfile.substr(lastposofcharacter + 2);
                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            folderfile.seekp(poswriter - getlineoffoldfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineoffoldfile.length()) {
                                folderfile << " ";
                                charnumber = charnumber + 1;
                            }
                            folderfile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            folderfile.seekp(poswriter - getlineoffoldfile.length() - 1);
                            folderfile << foldtest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/foldacc.txt";
        system(catread.c_str());
    }

    folderfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// REMOVE FILE VIEWED FROM FILE
int removefileviewfromfile(std::string file, bool systemcall) {
    std::fstream viewfile;
    viewfile.open(fileviewlocation.c_str(), std::ios::in | std::ios::out);
    if (viewfile.is_open() != true) {
        logwarning("Unable to Open FILE VIEW File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (viewfile.eof() != true && foundbit != true) {
            std::string getlineofviewfile = "";
            getline(viewfile, getlineofviewfile);
            if (getlineofviewfile != "") {
                int lastposofcharacter = getlineofviewfile.find_last_of("-");
                int maybe = getlineofviewfile.find(file);
                if (lastposofcharacter >= 0) {
                    std::string filetest = getlineofviewfile.substr(0, lastposofcharacter - 1);
                    if (filetest == file) {
                        long long int poswriter = viewfile.tellg();
                        std::string numberoftimes = getlineofviewfile.substr(lastposofcharacter + 2);
                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            viewfile.seekp(poswriter - getlineofviewfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineofviewfile.length()) {
                                viewfile << " ";
                                charnumber = charnumber + 1;
                            }
                            viewfile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            viewfile.seekp(poswriter - getlineofviewfile.length() - 1);
                            viewfile << filetest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/fileacc.txt";
        system(catread.c_str());
    }

    viewfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}


// REMOVE FILE EFFECTS FROM FILE
int removefileeffectfromfile(std::string file, bool systemcall) {
    std::fstream editfile;
    editfile.open(fileeditslocation.c_str(), std::ios::in | std::ios::out);
    if (editfile.is_open() != true) {
        logwarning("Unable to Open FILE EDIT File!", true);
        readwriteoperationfail.fetch_add(1);
        processingErrors.fetch_add(1);
        return -1;
    }


    int numbertosearch = 1;
    int current = 0;
    int saved = 0;
    while (current < numbertosearch) {
        bool foundbit = false;
        int linenumber = 0;
        int charlength = 0;
        while (editfile.eof() != true && foundbit != true) {
            std::string getlineofeditfile = "";
            getline(editfile, getlineofeditfile);
            if (getlineofeditfile != "") {
                int lastposofcharacter = getlineofeditfile.find_last_of("-");
                int maybe = getlineofeditfile.find(file);
                if (lastposofcharacter >= 0) {
                    std::string filetest = getlineofeditfile.substr(0, lastposofcharacter - 1);
                    if (filetest == file) {
                        long long int poswriter = editfile.tellg();
                        std::string numberoftimes = getlineofeditfile.substr(lastposofcharacter + 2);
                        if (numberoftimes == "1" || numberoftimes == "0") {
                            std::cout << "Clearing Entry..." << std::endl;
                            editfile.seekp(poswriter - getlineofeditfile.length() - 1);
                            int charnumber = 0;
                            while (charnumber < getlineofeditfile.length()) {
                                editfile << " ";
                                charnumber = charnumber + 1;
                            }
                            editfile << std::endl;
                            saved = saved + 1;
                        } else {
                            std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) - 1);
                            editfile.seekp(poswriter - getlineofeditfile.length() - 1);
                            editfile << filetest << " - " << newnumbertoinsert << std::endl;
                            saved = saved + 1;
                        }
                        foundbit = true;
                    }
                }
            }
            linenumber = linenumber + 1;
        }

        // IF FOUND BIT != TRUE, Then Create a New Entry in the File and Save
        if (foundbit != true) {
            std::cout << "NO ENTRY FOUND" << std::endl;
            current = current + 1;
        }
    }

    if (systemcall == false) {
        std::cout << "CURRENT FILE" << std::endl;
        std::string catread = "cat /home/listfiles/maclist.txt";
        system(catread.c_str());
    }

    editfile.close();

    entryAdded.fetch_add(saved);

    return saved;
}



// REMOVE IP ADDR STANDARD
// ERROR RETURNS
// -100 => Non-System Call
// -101 => Non-Root Call
// -102 => Num Too Large
int removeipSTANDARDfromfile(std::string ipaddr, std::string num, std::string useraccess, bool systemcall) {
    if (systemcall != true) {
        logwarning("Attempt to Clear IP Standard Not Called by SYSTEM!", true);
        return -100;
    }

    if (useraccess != "ROOT") {
        logwarning("Parameter to Clear Not From ROOT!", true);
        return -101;
    }

    if (stringtoint(num) > 3) {
        logwarning("NUM too large! Not Clearing!", true);
        return -102;
    }

    // CHECK WITH IP RAW BEFORE CONTINUING
    std::map<int, std::string> ipraw = readfromipraw(ipaddr);

    // FIX THIS - ADD ACTUAL CALLS AND CHECKS AGAINST LARGE NUMBERS






    return -1;
}


// REMOVE IP ADDR STRICT
int removeipSTRICTfromfile(std::string ipaddr, std::string num, std::string useraccess, bool systemcall) {
    if (systemcall != true) {
        logwarning("Attempt to Clear IP Standard Not Called by SYSTEM!", true);
        return -100;
    }

    if (useraccess != "ROOT") {
        logwarning("Parameter to Clear Not From ROOT!", true);
        return -101;
    }

    if (stringtoint(num) > 3) {
        logwarning("NUM too large! Not Clearing!", true);
        return -102;
    }

    // CHECK WITH IP RAW BEFORE CONTINUING
    std::map<int, std::string> ipraw = readfromipraw(ipaddr);

    // FIX THIS - ADD ACTUAL CALLS AND CHECKS AGAINST LARGE NUMBERS







    return -1;
}



// REMOVE PACKET FROM IPADDR RAW (MANUAL)
// ERROR RETURNS
// -100 => Non-System Call
// -101 => Non-Root Call
// -102 => Num Too Large
int removepacketfromipaddrrawfile(std::string ipaddr, std::string num, std::string useraccess, bool systemcall) {
    if (systemcall != true) {
        if (useraccess != "ROOT") {
            logwarning("Parameter to Clear Not From ROOT!", true);
            return -101;
        }
    }

    if (stringtoint(num) != 1) {
        logwarning("NUM NOT SET CORRECT! Not Clearing!", true);
        return -102;
    }


    std::map<int, float> ipinquestion = saveiptoTIMEBASEDFILE(ipaddr, 2, true, -1);
    if (ipinquestion[0] == 0) {
        // REMOVE FROM LIST
        // FIX THIS
    }
    
    


    // FIX THIS 

    return -1;
}






/////////////////////////////////////////
//// READ NUMBER IF NEEDED FROM FILE ////
/////////////////////////////////////////
// READ IP MAP FROM RAW
// NORMAL RETURN
// 0 => IPADDR
// 1 => RUNNING SEVERITY LAST 30 PACKETS
// 2 => LAST (NEWEST) PACKET
// 3 => FIRST PACKET
// 4 => NUMBER OF PACKETS RECEIVED
// 5 => MAX SEVERITY
// 6 => MIN SEVERITY
// 7 => MEAN SEVERITY
// 8 => DEV BAN
// 9 => PERMANENT BAN
// 10 => LIFTED BAN
// 11 => ASSOCIATE WITH HONEYPI
// 12 => NUMBER OF PACKETS IN LAST DAY
// 13 => COUNT OF DAYS WITH ZERO PACKETS
// 14 => NOTES
// 100 => POS IN FILE
// 101 => LENGTH OF STRING

// ERROR RETURN
// 0 => ERROR

// NOT FOUND RETURN
// 0 => NULL
std::map<int, std::string> readfromipraw(std::string ipaddr) {
    std::map<int, std::string> errormap;
    std::map<int, std::string> nullmap;
    std::map<int, std::string> statsmap;
    errormap[0] = "ERROR";
    nullmap[0] = "NULL";

    if (ipaddr == "") {
        logwarning("RECEIVED NULL IN READ FROM IP RAW", true);
        return errormap;
    }
    
    std::ifstream therawfile;
    therawfile.open(iplistraw.c_str());
    if (therawfile.is_open() != true) {
        logwarning("UNABLE TO OPEN IP RAW FILE! (STATS)", true);
        return errormap;
    }

    int raspberries = 0;
    std::string readfromfile = "";
    while (therawfile.eof() != true && raspberries < 1000) {
        getline(therawfile, readfromfile);
        if (readfromfile.length() > 15) {
            if (readfromfile.substr(0, ipaddr.length()) == ipaddr) {
                if (readfromfile.find(iprawseparator12) + 7 > readfromfile.length()) {
                    logwarning("RECEIVED INCONSISTENT IPRAW FILE!", true);
                    therawfile.close();
                    return errormap;
                }

                // TRY SANDBOXING CODE FOR READING IN CASE OF INCONSISTENT STATE!
                try {
                    statsmap[0] = readfromfile.substr(0,readfromfile.find(iprawseparator1));
                    statsmap[1] = readfromfile.substr(readfromfile.find(iprawseparator1) + 8,readfromfile.find(iprawseparator2) - readfromfile.find(iprawseparator1) - 8);
                    statsmap[2] = readfromfile.substr(readfromfile.find(iprawseparator2) + 8,readfromfile.find(iprawseparator3) - readfromfile.find(iprawseparator2) - 8);
                    statsmap[3] = readfromfile.substr(readfromfile.find(iprawseparator3) + 8,readfromfile.find(iprawseparator4) - readfromfile.find(iprawseparator3) - 8);
                    statsmap[4] = readfromfile.substr(readfromfile.find(iprawseparator4) + 8,readfromfile.find(iprawseparator5) - readfromfile.find(iprawseparator4) - 8);
                    statsmap[5] = readfromfile.substr(readfromfile.find(iprawseparator5) + 8,readfromfile.find(iprawseparator6) - readfromfile.find(iprawseparator5) - 8);
                    statsmap[6] = readfromfile.substr(readfromfile.find(iprawseparator6) + 8,readfromfile.find(iprawseparator7) - readfromfile.find(iprawseparator6) - 8);
                    statsmap[7] = readfromfile.substr(readfromfile.find(iprawseparator7) + 8,readfromfile.find(iprawseparator8) - readfromfile.find(iprawseparator7) - 8);
                    statsmap[8] = readfromfile.substr(readfromfile.find(iprawseparator8) + 8,readfromfile.find(iprawseparator9) - readfromfile.find(iprawseparator8) - 8);
                    statsmap[9] = readfromfile.substr(readfromfile.find(iprawseparator9) + 8,readfromfile.find(iprawseparator10) - readfromfile.find(iprawseparator9) - 8);
                    statsmap[10] = readfromfile.substr(readfromfile.find(iprawseparator10) + 8,readfromfile.find(iprawseparator11) - readfromfile.find(iprawseparator10) - 8);
                    statsmap[11] = readfromfile.substr(readfromfile.find(iprawseparator11) + 8,readfromfile.find(iprawseparator12) - readfromfile.find(iprawseparator11) - 8);
                    statsmap[12] = readfromfile.substr(readfromfile.find(iprawseparator12) + 8,readfromfile.find(iprawseparator13) - readfromfile.find(iprawseparator12) - 8);
                    statsmap[13] = readfromfile.substr(readfromfile.find(iprawseparator13) + 8,readfromfile.find(iprawseparator14) - readfromfile.find(iprawseparator13) - 8);
                    statsmap[14] = readfromfile.substr(readfromfile.find(iprawseparator14) + 8,readfromfile.length() - readfromfile.find(iprawseparator14));
                    statsmap[100] = inttostring(therawfile.tellg());
                    statsmap[101] = inttostring(readfromfile.length());

                    
                    
                    if (statsmap[0] != ipaddr) {
                        therawfile.close();
                        logwarning("READ DID NOT RETURN CORRECT UPON REVIEWING IP ADDR!" + statsmap[0] + " wanted " + ipaddr, true);
                        return errormap;
                    }
                    therawfile.close();
                    return statsmap;
                }
                catch(...) {
                    therawfile.close();
                    logwarning("RECEIVED INCONSISTENT IPRAW FILE!", true);
                    return errormap;
                }
            }
        }
        raspberries = raspberries + 1;
    }

    if (therawfile.eof() == true) {
        therawfile.close();
        return nullmap;
    } else {
        therawfile.close();
        return errormap;
    }
    therawfile.close();
    return errormap;
}






// CHECK FOR IP IN FILES
// RETURNS 1 (YES)/0 (NO)/-# (ERROR)
int ipinstandardfile(std::string ipaddr) {
    if (ipaddr == "") {
        return -1;
    }

    std::ifstream ipstandard;
    ipstandard.open(ipliststandardlocation.c_str());
    if (ipstandard.is_open() != true) {
        return -2;
    }

    std::string returnedvalues = "";
    while (ipstandard.eof() != true) {
        getline(ipstandard, returnedvalues);
        if (returnedvalues == ipaddr) {
            return 1;
        }
    }

    return 0;
}


// RETURNS TRUE (YES)/FALSE (NO)
int ipinstrictfile(std::string ipaddr) {
    if (ipaddr == "") {
        return -1;
    }

    std::ifstream ipstrict;
    ipstrict.open(ipliststrictlocation.c_str());
    if (ipstrict.is_open() != true) {
        return -2;
    }

    std::string returnedvalues = "";
    while (ipstrict.eof() != true) {
        getline(ipstrict, returnedvalues);
        if (returnedvalues == ipaddr) {
            return 1;
        }
    }

    return 0;
}






// RETURNS COG FILES THAT NEED TO BE READ
// NORMAL RETURN
// 0 => STATUS ([1]=OK; [0]=ERROR)
// 1 => COGS IN NORMAL PROCESSING
// 2 => COGS HELD FOR REVIEW
// 3 => MISPLCAED COGS

// ERROR RETURN
// 0[0] => ERROR
std::map<int, std::map<int, std::string>> readcogprocessinglocations() {
    std::map<int, std::map<int, std::string>> errormap;
    errormap[0][0] = "ERROR";

    // FIX THIS ADD LIST OF COGS!

    std::string path = "/home/listfiles";

    for (const auto & entry : std::filesystem::directory_iterator(path)) {
        std::cout << entry.path() << std::endl;
        std::string test = entry.path();
    }


    return errormap;
}



// RETURN LIST OF FILES FOR IP ADDRESS
std::map<int, std::string> readlistofcogsforIP(std::string ipaddr) {
    std::map<int, std::string> errormap;
    errormap[0] = "ERROR";


    // FIX THIS ADD LIST OF FILES


    return errormap;
}




// READ COG FILE TO CONSOLE
std::string readfromtoconsole(std::string filelocation) {


    // FIX THIS PRINT COG TO CONSOLE


    return "ERROR";
}





// (MANUAL) CHANGE COG FILE LOCATION TO FINISHED
int changecogfiletofinish(std::string filelocation) {



    // FIX THIS


    return -1;
}







/////////////////////////////////////////
//// MAINTAINENCE SCRIPT FOR IP LIST ////
/////////////////////////////////////////
// RAN ONCE DAILY!!!
// 0 => Number of IPs ADDED
// 1 => Number of IPs STAYED
// 2 => Number of IPs REMOVED
// fix this - change this
std::map<int, std::map<int, std::string>> runipstandardstrictpurginglist(bool systemcall, bool stopaterrors, bool resetiferrors) {
    std::map<int, std::map<int, std::string>> maintenancemap;


    // FIX THIS

    
    return maintenancemap;
}



// FIX THIS - ADD SECOND MAINTENANCE SCRIPT FOR 3rd DAY (STRICT)

    




////////////////////////////////////////////////////
// CHANGE ENCRYPTION METHOD BACK TO STANDARD FILE //
////////////////////////////////////////////////////
// Outputs File Location
std::string unencryptcog(std::string inputfile, std::string clientIP) {
    if (inputfile == "") {
        logwarning("Unencrypt Input File was NULL", true);
        return "ERROR";
    }

    // OPEN THE FILE AND READ THE CONTENTS
    std::string inputdata = "";
    std::ifstream encryptedcogfile;
    encryptedcogfile.open(inputfile.c_str());
    loginfo("Converting File " + inputfile, true);
    if (encryptedcogfile.is_open() == true) {
        std::string praise = "";
        while (encryptedcogfile.eof() != true) {
            std::string buf = "";
            getline(encryptedcogfile, buf);
            inputdata = inputdata + buf + "\n";
        }
    } else {
        logwarning("Unencrypt unable to open COG File!", true);
        return "ERROR";
    }

    // CONVERT DATA INTO UNENCRYPTED FORMAT
    encryptionchange.fetch_add(1);
    std::string outputdata = ucrypt_decrypt(inputdata);
    if (outputdata == "" || outputdata == "ERROR") {
        logwarning("Error Caught in ucrypt()", true);
        return "ERROR";
    }

    // CLOSE STREAM AND WRITE TO NEW FILE
    encryptedcogfile.close();
    std::ofstream ucryptedstream;
    std::string newfilelocation = "/home/crashlogs/UN" + clientIP + ".txt";
    ucryptedstream.open(newfilelocation.c_str());
    if (ucryptedstream.is_open() == true) {
        ucryptedstream << outputdata;
        std::string removeprevious = "rm " + inputfile;
        system(removeprevious.c_str());
    } else {
        logwarning("UCrypt Cog Unable to Open Output File Destination", true);
        return "ERROR";
    }

    ucryptedstream.close();
    inputdata.clear();
    outputdata.clear();
    return newfilelocation;
}















////////////////////////////////////////////////////////////////
////// PROCESS REPORT FOR THE COMMAND TO WORK (MAIN LOOP) //////
////////////////////////////////////////////////////////////////

// EXPECTED RETURN
// RETURN 0 - COMPLETED SUCCESSFULLY
// RETURN 1 - MOVE DELAYED TILL PARENT OPERATION COMPLETES

// UNEXPECTED RETURNS
// RETURN 10 - FILE STREAM NOT OPENED CORRECTLY
// RETURN 11 - READ/WRITE ERROR
// RETURN 12 - LOGICAL IO ERROR
// RETURN 200 - Sub-Function Mismatch (Username)
// RETURN 201 - Sub-Function Mismatch (Passwords)
// RETURN 202 - Sub-Function Mismatch (Commands)
// RETURN 203 - Sub-Function Mismatch (Folders)
// RETURN 204 - Sub-Function Mismatch (Files Viewed)
// RETURN 205 - Sub-Function Mismatch (File Edits (Transitions))
// RETURN 206 - Sub-Function Mismatch (Extra)
// RETURN 207 - Sub-Function Mismatch (IP ADDR INSERT)
// RETURN 251 - RECEIVED ERROR IN CACHING FILES
// RETURN 252 - RECEIVED LOCAL CALL WITH NO COG
// RETURN 253 - RECEIVED NULL CASE FOR IP ADDRESS
// RETURN 254 - NOT VALID FILENAME
// RETURN 255 - SHOULD NEVER REACH HERE
int processReport(std::string filename, std::string clientIP, bool localcall, std::string coglocale) {

    int linenumber = 0;

    // CHECK FOR VALID PARAMETERS
    if (filename == "" && localcall == false) {
        if (localcall != true) {
            logwarning("Log File NULL: " + filename, true);
            return 254;
            return 254;
        } else {
            filename = "/home/crashlogs/DOEN" + coglocale + ".txt";
        }
    }

    if (localcall == true && filename == "") {
        if (coglocale == "" || coglocale == "ERROR") {
            logwarning("RECEIVED LOCAL WITH NO COG!", true);
            return 252;
        }
    }

    if (filename == "/home/testreport.txt") {
        std::cout << "DEBUG MODE" << std::endl;
    }

    // THIS NEXT
    if (clientIP == "" || clientIP == "ERROR") {
        // NOT CONTINUE AND RETURN 0 IF EVERYTHING IS FINISHED CORRECTLY
        logwarning("Received Null Case for ClientIP Address! (Process)" , true);
        return 253;
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
    int numberoflineends = 0;

    if (localcall == true) std::cout << "Starting to Analyze!" << std::endl;


    while (completionproc != true && reportstream.eof() != true) {
        reportstream.getline(lineraw, 2048);

        // CONVERT TO STRING FOR ANALYSIS
        std::string linestr = lineraw;
        
        // DEBUG HANDLER
        if (localcall == true) {
            std::cout << linenumber << ": " << linestr.length() << ": " << lineraw << std::endl;
            linenumber = linenumber + 1;
        }

        // MAKE SURE IT IS NOT BLANK
        if (linestr.length() > 2) {
            numberoflineends = 0;
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
                if (localcall == true) std::cout << "MAPPING" << std::endl;
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
                                        usernameacc = linestr.substr(previousstart, currentchar - previousstart);
                                        previousstart = currentchar + 4;
                                        currentchar = currentchar + 1;
                                    }
                                } else if (currentstring == ")") {
                                    passwordacc = linestr.substr(previousstart + 2, currentchar - previousstart - 1);
                                    passwordacc = passwordacc.substr(0, passwordacc.length() - 1);
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
                    std::string fileexec = linestr.substr(1, linestr.length() - 2);
                    filesmap.insert({filestranonreport, fileexec});
                    filestranonreport = filestranonreport + 1;
                } else if (ipaddr == true) {
                    std::string ipaddr = linestr.substr(1, linestr.length() - 2);
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
                numberoflineends = 0;
            }
        } else {
            numberoflineends = numberoflineends + 1;
            if (numberoflineends >= 20) {
                completionproc = true;
            }
        }
    }


    // PRINT EVERYTHING TO CONSOLE IF DEBUG TEST REPORT IS USED
    if (localcall == true) {
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

    sleep(3);
    



    // PUT ALL THE INFORMATION IN ITS CORECT SPOT AND KEEP GOING!
    std::string dash = "-";
    std::string colon = ":";
    std::string dateofyear = inttostring(day) + dash + inttostring(month) + dash + inttostring(year) + " = " + inttostring(hour) + colon + inttostring(minute) + colon + inttostring(second);
    if (localcall == true) std::cout << "TIME SEEN " << dateofyear << std::endl;



    // SAVE ALL USERNAMES TO FILE
    if (localcall == true) std::cout << "STARTING USERNAME..." << std::endl;
    int changedusernames = saveusernamestofile(usercombomap, !(localcall));
    if (localcall == true) std::cout << changedusernames << " Entries Modified" << std::endl; 


    // SAVE ALL PASSWORDS TO FILE
    if (localcall == true) std::cout << "STARTING PASSWORD..." << std::endl;
    int changedpasswords = savepasswordstofile(passcombomap, !(localcall));
    if (localcall == true) std::cout << changedpasswords << " Entries Modified" << std::endl;


    // COMMANDS
    if (localcall == true) std::cout << "STARTING COMMANDS..." << std::endl;
    int changedcommands = savecommandstofile(commandmap, !(localcall));
    if (localcall == true) std::cout << changedcommands << " Entries Modified" << std::endl;


    // FOLDERS
    if (localcall == true) std::cout << "STARTING FOLDERS..." << std::endl;
    int changedfolders = savefoldertofile(filesmap, !(localcall));
    if (localcall == true) std::cout << changedfolders << " Entries Modified" << std::endl;


    // FILES CHANGED
    if (localcall == true) std::cout << "STARTING FILES..." << std::endl;
    int changedfiles = savefilesviewedtofile(filechangesmap, !(localcall));
    if (localcall == true) std::cout << changedfiles << " Entries Modified" << std::endl;


    // FILE EDITS MAP
    if (localcall == true) std::cout << "STARTING TRANSITIONS..." << std::endl;
    int changedtransitions = savefileeffectstofile(fileeditsmap, !(localcall));
    if (localcall == true) std::cout << changedtransitions << " Entries Modified" << std::endl;


    // EXTRA MAP SAVE
    if (localcall == true) std::cout << "STARTING EXTRA MAP..." << std::endl;
    int changedextramap = saveextraopttofile(extramap, !(localcall));
    if (localcall == true) std::cout << changedextramap << " Entried Modified" << std::endl;





    // DETERMINE IF ANY ABOVE IS NULL||ERROR AND DO NOT CONTINUE
    if (changedusernames != usercombomap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Username Mismatch]", true);
        logwarning("Compared: " + inttostring(changedusernames) + " against " + inttostring(usercombomap.size()), true);
        return 200;
    }

    if (changedpasswords != passcombomap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Password Mismatch]", true);
        logwarning("Compared: " + inttostring(changedpasswords) + " against " + inttostring(passcombomap.size()), true);
        return 201;
    }

    if (changedcommands != commandmap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Command Mismatch]", true);
        logwarning("Compared: " + inttostring(changedcommands) + " against " + inttostring(commandmap.size()), true);
        return 202;
    }

    if (changedfolders != filesmap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Folder Mismatch]", true);
        logwarning("Compared: " + inttostring(changedfolders) + " against " + inttostring(filesmap.size()), true);
        return 203;
    }

    if (changedfiles != filechangesmap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Files Mismatch]", true);
        logwarning("Compared: " + inttostring(changedfiles) + " against " + inttostring(filechangesmap.size()), true);
        return 204;
    }

    if (changedtransitions != fileeditsmap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Transition Mismatch]", true);
        logwarning("Compared: " + inttostring(changedtransitions) + " against " + inttostring(fileeditsmap.size()), true);
        return 205;
    }
    
    if (changedextramap != extramap.size()) {
        logwarning("Error Occurred in Consistency (Process) [Extra Effect Mismatch]", true);
        logwarning("Compared: " + inttostring(changedextramap) + " against " + inttostring(extramap.size()), true);
        return 206;
    }






    // DETERMINE SEVERITY
    std::map<int, std::map<std::string, float>> severitymaps = determineseverity(usercombomap, passcombomap, commandmap, filesmap, filechangesmap, fileeditsmap, extramap, ipaddrmap, 0, 0, 0, 0, 0, method);

    
    // DETERMINE IP ADDRESS PLACEMENT
    std::map<int, std::map<std::string, float>> errormap;
    errormap[0]["ERROR"] = -1;
    if (severitymaps == errormap) {
        return 251;
    }


    // ELSE, CONTINUE WITH REPORT
    int ipaddrreturned = saveipaddrPREMIUMFILE(ipaddrmap, severitymaps, true);
    if (ipaddrreturned != ipaddrmap.size()) {
        logwarning("Error Occurred in Consistency (Process) [IP ADDR Mismatch!]", true);
        logwarning("Compared: " + inttostring(ipaddrreturned) + " against " + inttostring(ipaddrmap.size()), true);
        return 207;
    }



    // MOVE COG TO NEW POSITION
    int time2 = time(NULL);
    int mvresult = normalfinalizecog(filename, clientIP + "_" + std::to_string(time2), !(localcall), clientIP);
    if (mvresult == 0) {
        return 0;
    } else {
        return 250;
    }


    return 255;
}






///////////////////////////////////////////////////////////
////// CACHE ALL DATABASES FOR SEVERITY MEASUREMENTS //////
////// INTO RAM (UPDATE/RESTORE RAM) //////////////////////
///////////////////////////////////////////////////////////

// "bash"
std::map<std::string, float> cachecommandseverity() {
    std::map<std::string, float> tempcache;
    std::map<std::string, float> errormap;
    errormap["ERROR"] = -1;
    
    // OPEN FILE
    std::ifstream commandfile;
    commandfile.open("/home/databases/command_severity.txt");
    if (commandfile.is_open() != 1) {
        logwarning("Unable to open command file!", true);
        return errormap;
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
            tempcache.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return errormap;
        }
    }

    return tempcache;
}


// "/home"
std::map<std::string, float> cachefileaccess() {
    std::map<std::string, float> tempcache;
    std::map<std::string, float> errormap;
    errormap["ERROR"] = -1;
    
    // OPEN FILE
    std::ifstream fileaccess;
    fileaccess.open("/home/databases/file_access_severity.txt");
    if (fileaccess.is_open() != 1) {
        logwarning("Unable to open access file!", true);
        return errormap;
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
            tempcache.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return errormap;
        }
    }
    return tempcache;
}


// "ADD uishfes INTO /home/test.txt:1"
std::map<std::string, float> cachefileedit() {
    std::map<std::string, float> tempcache;
    std::map<std::string, float> errormap;
    errormap["ERROR"] = -1;

    // EDIT FILE
    std::ifstream editfile;
    editfile.open("/home/databases/file_edit_severity.txt");
    if (editfile.is_open() != 1) {
        logwarning("Unable to open EDIT file!", true);
        return errormap;
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
            tempcache.insert({restofmessage, severitymeasured23});
        } else {
            logwarning("Received an Invalid Combination!", true);
            return errormap;
        }
    }
    return tempcache;
}


// "/home/test.txt"
std::map<std::string, float> cachefilechanges() {
    std::map<std::string, float> tempcache;
    std::map<std::string, float> errormap;
    errormap["ERROR"] = -1;

    // EDIT FILE
    std::ifstream changefile;
    changefile.open("/home/databases/file_changes_severity.txt");
    if (changefile.is_open() != 1) {
        logwarning("Unable to open CHANGE file!", true);
        return errormap;
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
            return errormap;
        }
    }
    return tempcache;
}


// Main Loop
// 0 => Command Severity
// 1 => Folders Viewed
// 2 => Files Changes
// 3 => Files Viewed
std::map<int, std::map<std::string, float>> cacheseverity() {
    std::map<int, std::map<std::string, float>> errormap;
    errormap[0]["ERROR"] = -1;

    int returnvalues2;
    std::map<int, std::map<std::string, float>> returntables;
    returntables[0] = cachecommandseverity();
    returntables[1] = cachefileaccess();
    returntables[2] = cachefileedit();
    returntables[3] = cachefilechanges();

    if (returntables[0]["ERROR"] == -1 || returntables[1]["ERROR"] == -1 || returntables[2]["ERROR"] == -1 || returntables[3]["ERROR"] == -1) {
        logcritical("MAP VARIABLES SAID", false);
        if (returntables[0]["ERROR"] == -1) {
            logcritical("FAIL AT 0", true);
        }
        if (returntables[1]["ERROR"] == -1) {
            logcritical("FAIL AT 1", true);
        }
        if (returntables[2]["ERROR"] == -1) {
            logcritical("FAIL AT 2", true);
        }
        if (returntables[3]["ERROR"] == -1) {
            logcritical("FAIL AT 3", true);
        }
        return errormap;
    }

    return returntables;
}


