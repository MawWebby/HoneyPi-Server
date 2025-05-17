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


// FILE LOCATIONS
const std::string usernamelocation = "/home/listfiles/userstream.txt";
const std::string passwordlocation = "/home/listfiles/passstream.txt";
const std::string commandlocation = "/home/listfiles/cmdrun.txt";




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







// FIX THIS - ADD ANALYZING COGS HEADER
// + user test
// + pass test
// + comm test

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
        while (usernamefile.eof() != true && foundbit != true) {
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

                        // fix this - writing position for new and make sure number is correct!
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        //std::ofstream userfileWRITE;
                        //userfileWRITE.open(usernamelocation.c_str());

                        usernamefile.seekp(poswriter - getlineofuserfile.length() - 1);
                        usernamefile << usertest << " - " << newnumbertoinsert << std::endl;
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

                        // fix this - writing position for new and make sure number is correct!
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        //std::ofstream userfileWRITE;
                        //userfileWRITE.open(usernamelocation.c_str());

                        passwordfile.seekp(poswriter - getlineofpassfile.length() - 1);
                        passwordfile << passtest << " - " << newnumbertoinsert << std::endl;
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

                        // fix this - writing position for new and make sure number is correct!
                        std::string newnumbertoinsert = inttostring(stringtoint(numberoftimes) + 1);
                        //std::ofstream userfileWRITE;
                        //userfileWRITE.open(usernamelocation.c_str());

                        commandfile.seekp(poswriter - getlineofcomfile.length() - 1);
                        commandfile << commandtest << " - " << newnumbertoinsert << std::endl;
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
                        foundbit = true;
                        std::string numberoftimes = getlineofuserfile.substr(lastposofcharacter + 2);

                        // fix this - writing position for new and make sure number is correct!
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
                            //std::ofstream userfileWRITE;
                            //userfileWRITE.open(usernamelocation.c_str());
    
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
                        foundbit = true;
                        std::string numberoftimes = getlineofpassfile.substr(lastposofcharacter + 2);

                        // fix this - writing position for new and make sure number is correct!
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
                            //std::ofstream userfileWRITE;
                            //userfileWRITE.open(usernamelocation.c_str());
    
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
                        foundbit = true;
                        std::string numberoftimes = getlineofcommfile.substr(lastposofcharacter + 2);

                        // fix this - writing position for new and make sure number is correct!
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
                            //std::ofstream userfileWRITE;
                            //userfileWRITE.open(usernamelocation.c_str());
    
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

// RETURN 10 - FILE STREAM NOT OPENED CORRECTLY
// RETURN 11 - READ/WRITE ERROR
// RETURN 12 - LOGICAL IO ERROR
// RETURN 254 - NOT VALID FILENAME
// RETURN 255 - SHOULD NEVER REACH HERE
int processReport(std::string filename, std::string clientIP) {

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
    int numberoflineends = 0;

    std::cout << "Starting to Analyze!" << std::endl;


    while (completionproc != true && reportstream.eof() != true) {
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
                                        usernameacc = linestr.substr(previousstart, currentchar - previousstart);
                                        previousstart = currentchar + 4;
                                        currentchar = currentchar + 1;
                                    }
                                } else if (currentstring == ")") {
                                    passwordacc = linestr.substr(previousstart, currentchar - previousstart);
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
    // FIX THIS JUST FOR IF TRUE CASE
    if (filename == "/home/testreport.txt" || true) {
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
    std::cout << "TIME SEEN " << dateofyear << std::endl;



    // SAVE ALL USERNAMES TO FILE
    std::cout << "STARTING USERNAME" << std::endl;
    std::cout << saveusernamestofile(usercombomap, true) << std::endl; 



    // SAVE ALL PASSWORDS TO FILE
    std::cout << "STARTING PASSWORD" << std::endl;
    std::cout << savepasswordstofile(passcombomap, true) << std::endl;

    // COMMANDS
    std::cout << "STARTING COMMANDS" << std::endl;
    std::cout << savecommandstofile(commandmap, true) << std::endl;


















    // THIS NEXT
    if (clientIP == "" || clientIP == "ERROR") {
        // NOT CONTINUE AND RETURN 0 IF EVERYTHING IS FINISHED CORRECTLY
    }

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


