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
std::string ipsafetyRAM[1];
bool runningport80 = true;
bool port80runningstatus = false;
int packetspam = 0;
bool waiting230 = false;



// HTML VARIABLES
std::string mainhtmlpayload;
std::string pricinghtmlpayload;
std::string httpforbidden = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: 25\n\n<h1>504: Gateway Time-Out</h1>";
std::string httpservererror = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: 72\n\n<h1>505: An Internal Server Error Occurred, Please Try Again Later.</h1>";



// FILES 
//std::fstream ipliststrict;         // IP BLOCKLIST TABLE (STRICT 90 DAY REMOVAL W/O EXCEPTIONS)
//std::fstream ipliststandard;       // IP BLOCKLIST TABLE (STANDARD 45 DAY REMOVAL W/ EXCEPTIONS)
//std::fstream iplistsmoreinfo;      // INFO ABOUT IP REPORTED/REPORTS/LATEST REPORT/EXPIRATION DATE
//std::fstream maclist;              // MAC ADDRESSES FOR HONEYPIS
//std::fstream severitylist;         // SEVERITY LIST OF OP ATTACKS
//std::fstream acpmac;               // JSON LIST OF ACCOUNTS/MAC/API/ETC.
//std::fstream blockedipstream;      // SERVER IP BLOCKLIST
//std::fstream config1;              // serverconfig1
std::fstream cogfile[256];           // Crashlogs
std::string filenameforcogs[256];    // FILES NAMES FOR COGS (Crashlogs)
int cogswaiting = 0;
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
const char* blockedipstreamfile = "/home/listfiles/ipsafety.txt";
const char* config1file = "/home/listfiles/serverconfig1.txt";
const char* userstreamfile = "/home/listfiles/userstream.txt";
const char* passstreamfile = "/home/listfiles/passstream.txt";
const char* serverdumpfile = "/home/serverdump/serverdump.txt";
const char* serverlogfilefile = "/home/serverdump/log.txt";
const char* foldersaccessedfile = "/home/listfiles/foldacc.txt";
const char* filesaccessedfile = "/home/listfiles/fileacc.txt";
const char* cmdrunfile = "/home/listfiles/cmdrun.txt";
const char* cogfolder = "/home/crashlogs";
const char* mainhtml = "/home/htmlmainweb/index.html";
const char* pricehtml = "/home/htmlmainweb/pricing.html";
const char* htmlfolder = "/home/htmlmainweb";
const char* filearguments = "ios::in | ios::out";



// FILE LOCK VARIABLES
bool ipliststrictlock = false;
bool ipliststandardlock = false;
bool ipsafetylock = false;
bool userstreamlock = false;


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
// 1 - PACKET OVERFLOW DETECTION PORT 80
// 2 - 15-MINUTE TIMER FOR PORT 80
// 3 - 1-Hour Maintenance Timer
// 4 - 6-Hour Maintenance Timer
// 5 - 30-Minute Wait for COGs




//////////////////////
//// TIMER SCRIPT ////
//////////////////////
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





/////////////////////////////////////
//// GENERATE API RANDOM STRINGS ////
/////////////////////////////////////
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

    return random_string;
}

std::string generateRandomFileName() {
    loginfo("CREATING NEW RANDOM FILENAME");

    timedetector();

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
    std::string random_string = std::to_string(currenthour) + "_" + std::to_string(currentdays) + "_" + std::to_string(currentyear);
    for (int i = 0; i < 6; ++i) {
        random_string += CHARACTERS[distribution(generator)];
    }

    return random_string;
}




////////////////////////////////////////////
//// CHECK FILES BEFORE FILE OPEARTIONS ////
////////////////////////////////////////////
int checkstringinstrictDB(std::string stringtocheck) {
    std::ifstream ipliststrict;
    ipliststrict.open(ipliststrictfile);
    int timer = 0;
    int timermax = 5;
    if (ipliststrict.is_open() != true) {
        // UNABLE TO OPEN FILE, RETURN 2;
        ipliststrict.close();
        return 2;
    } else {
        std::string currentstring;
        while (true) {
            getline(ipliststrict, currentstring);
            if (currentstring == stringtocheck) {
                // STRING MATCHES, RETURN 1
                ipliststrict.close();
                return 1;
            } else {
                if (currentstring == "") {
                    timer = timer + 1;
                    if (timer >= timermax) {
                        // STRING NOT FOUND
                        ipliststrict.close();
                        return 0;
                    }
                } else {
                    timer = 0;
                }
            }
        }
    }
    return 2;
}

int checkstringinstandardDB(std::string stringtocheck) {
    std::ifstream ipliststandard;
    ipliststandard.open(ipliststandardfile);
    int timer = 0;
    int timermax = 5;
    if (ipliststandard.is_open() != true) {
        // UNABLE TO OPEN FILE, RETURN 2;
        ipliststandard.close();
        return 2;
    } else {
        std::string currentstring;
        while (true) {
            getline(ipliststandard, currentstring);
            if (currentstring == stringtocheck) {
                // STRING MATCHES, RETURN 1
                ipliststandard.close();
                return 1;
            } else {
                if (currentstring == "") {
                    timer = timer + 1;
                    if (timer >= timermax) {
                        // STRING NOT FOUND
                        ipliststandard.close();
                        return 0;
                    }
                } else {
                    timer = 0;
                }
            }
        }
    }
    return 2;
}

int checkstringinIPSAFETY(std::string stringtocheck) {
    std::ifstream blockedipstream;
    blockedipstream.open(blockedipstreamfile);
    int timer = 0;
    int timermax = 5;
    if (blockedipstream.is_open() != true) {
        // UNABLE TO OPEN FILE, RETURN 2;
        blockedipstream.close();
        return 2;
    } else {
        std::string currentstring;
        while (true) {
            getline(blockedipstream, currentstring);
            if (currentstring == stringtocheck) {
                // STRING MATCHES, RETURN 1
                blockedipstream.close();
                return 1;
            } else {
                if (currentstring == "") {
                    timer = timer + 1;
                    if (timer >= timermax) {
                        // STRING NOT FOUND
                        blockedipstream.close();
                        return 0;
                    }
                } else {
                    timer = 0;
                }
            }
        }
    }
    return 2;
}

int checkstringinUSERStream(std::string stringtocheck) {
    std::ifstream userstream;
    userstream.open(userstreamfile);
    int timer = 0;
    int timermax = 5;
    int runtime = 0;
    if (userstream.is_open() != true) {
        // UNABLE TO OPEN FILE, RETURN null;
        userstream.close();
        return -1;
    } else {
        std::string currentstring;
        while (true) {
            getline(userstream, currentstring);
            if (currentstring == stringtocheck) {
                // STRING MATCHES, RETURN VALUE
                userstream.close();
                return runtime;
            } else {
                if (currentstring == "") {
                    timer = timer + 1;
                    if (timer >= timermax) {
                        // STRING NOT FOUND
                        userstream.close();
                        return 0;
                    }
                } else {
                    timer = 0;
                }
            }
            runtime = runtime + 1;
        }
    }
    return -1;
}





///////////////////////////////////////////
////// THE FORBIDDEN FILE OPERATIONS //////
///////////////////////////////////////////
int writetoipliststrict(std::string writedata, int position, bool end, bool forcelock) {
    if (forcelock == true) {
        ipliststrictlock = false;
    }

    if (ipliststrictlock == true) {
        logcritical("UNABLE TO WRITE TO IP LIST STRICT FILE!");
        logcritical("ipliststrictlock = true");
        return 2;
    } else {
        // CHECK FOR STRING TO ALREADY BE IN DB
        ipliststrictlock = true;
        int checkcommand = checkstringinstrictDB(writedata);
        if (checkcommand == 0) {
            std::ofstream ipliststrict;
            if (end != true) {
                ipliststrict.open(ipliststrictfile);
            } else {
                ipliststrict.open(ipliststrictfile, std::ios::app);
            }
            if (ipliststrict.is_open() == true) {
                ipliststrict << writedata << '\n';
                if (ipliststrict.fail()) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO IPLISTSTRICT");
                    if (ipliststrict.bad() == true) {
                        logcritical("I/O ERROR OCCURRED");
                    }
                    startupchecks = startupchecks + 1;
                    ipliststrict.close();
                    ipliststrictlock = false;
                    return 1;
                } else {
                    // EXPECTED OUTCOME
                    ipliststrict.close();
                    ipliststrictlock = false;
                    return 0;
                }
            } else {
                ipliststrict.close();
                ipliststrictlock = false;
                return 1;
            }
        } else {
            if (checkcommand == 1) {
                // EXPECTED OUTCOME - DUPLICATE STRING
                ipliststrictlock = false;
                return 0;
            } else {
                ipliststrictlock = false;
                return 1;
            }
        }
    }
    ipliststrictlock = false;
    return 1;
}

int writetoipliststandard(std::string writedata, int position, bool end, bool forcelock) {
    if (forcelock == true) {
        ipliststandardlock = false;
    }

    if (ipliststandardlock == true) {
        logcritical("UNABLE TO WRITE TO IP LIST STANDARD FILE!");
        logcritical("ipliststrictlock = true");
        return 2;
    } else {
        // CHECK FOR STRING TO ALREADY BE IN DB
        ipliststandardlock = true;
        int checkcommand = checkstringinstrictDB(writedata);
        if (checkcommand == 0) {
            std::ofstream ipliststandard;
            if (end != true) {
                ipliststandard.open(ipliststandardfile);
            } else {
                ipliststandard.open(ipliststandardfile, std::ios::app);
            }
            if (ipliststandard.is_open() == true) {
                ipliststandard << writedata << '\n';
                if (ipliststandard.fail()) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO ipliststandard");
                    if (ipliststandard.bad() == true) {
                        logcritical("I/O ERROR OCCURRED");
                    }
                    startupchecks = startupchecks + 1;
                    ipliststandard.close();
                    ipliststandardlock = false;
                    return 1;
                } else {
                    // EXPECTED OUTCOME
                    ipliststandard.close();
                    ipliststandardlock = false;
                    return 0;
                }
            } else {
                ipliststandard.close();
                ipliststandardlock = false;
                return 1;
            }
        } else {
            if (checkcommand == 1) {
                // EXPECTED OUTCOME - DUPLICATE STRING
                ipliststandardlock = false;
                return 0;
            } else {
                ipliststandardlock = false;
                return 1;
            }
        }
    }
    ipliststandardlock = false;
    return 1;
}

// MORE ON MORE INFO IP LISTS/ADD ABILITY TO MODIFY LINES IF NEEDED FOR CERTAIN IP ADDRESSES/REPEAT/TIME/ETC.

int writetoblockediplist(std::string writedata, bool end, bool forcelock) {
    if (forcelock == true) {
        ipsafetylock = false;
    }

    if (ipsafetylock == true) {
        logcritical("UNABLE TO WRITE TO IPSAFETY FILE!");
        logcritical("ipliststrictlock = true");
        return 2;
    } else {
        // CHECK FOR STRING TO ALREADY BE IN DB
        ipsafetylock = true;
        int checkcommand = checkstringinstrictDB(writedata);
        if (checkcommand == 0) {
            std::ofstream ipsafety;
            if (end != true) {
                ipsafety.open(blockedipstreamfile);
            } else {
                ipsafety.open(blockedipstreamfile, std::ios::app);
            }
            if (ipsafety.is_open() == true) {
                ipsafety << writedata << '\n';
                if (ipsafety.fail()) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO ipliststandard");
                    if (ipsafety.bad() == true) {
                        logcritical("I/O ERROR OCCURRED");
                    }
                    startupchecks = startupchecks + 1;
                    ipsafety.close();
                    ipsafetylock = false;
                    return 1;
                } else {
                    // EXPECTED OUTCOME
                    ipsafety.close();
                    ipsafetylock = false;
                    return 0;
                }
            } else {
                ipsafety.close();
                ipsafetylock = false;
                return 1;
            }
        } else {
            if (checkcommand == 1) {
                // EXPECTED OUTCOME - DUPLICATE STRING
                ipsafetylock = false;
                return 0;
            } else {
                ipsafetylock = false;
                return 1;
            }
        }
    }
    ipsafetylock = false;
    return 1;
}

int writetoUSERStream(std::string username, bool forcelock) {
    if (forcelock == true) {
        userstreamlock = false;
    }

    if (userstreamlock == true) {
        logcritical("UNABLE TO WRITE TO USERSTREAM FILE!");
        logcritical("ipliststrictlock = true");
        return 2;
    } else {
        // CHECK FOR STRING TO ALREADY BE IN DB
        userstreamlock = true;
        int checkcommand = checkstringinUSERStream(username);
        if (checkcommand == -1) {
            logcritical("CHECK OPERATION FAILED!");
            return 2;
        } else {
            std::ofstream userstream;
            if (checkcommand == 0) {
                userstream.open(userstreamfile, std::ios::app);
                userstream << username << '\n';
                if (userstream.fail()) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO USERSTREAM");
                    if (userstream.bad() == true) {
                        logcritical("I/O ERROR OCCURRED");
                    }
                    startupchecks = startupchecks + 1;
                    userstream.close();
                    userstreamlock = false;
                    return 1;
                } else {
                    // EXPECTED OUTCOME
                    userstream.close();
                    userstreamlock = false;
                    return 0;
                }
            } else {
                userstream.open(userstreamfile);
                userstream.seekp(checkcommand + 8);
                userstream << username << '\n';
                if (userstream.fail()) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO USERSTREAM");
                    if (userstream.bad() == true) {
                        logcritical("I/O ERROR OCCURRED");
                    }
                    startupchecks = startupchecks + 1;
                    userstream.close();
                    userstreamlock = false;
                    return 1;
                } else {
                    // EXPECTED OUTCOME
                    userstream.close();
                    userstreamlock = false;
                    return 0;
                }
            }
        }
    }
}





/////////////////////////////
//// COG FILE OPERATIONS ////
/////////////////////////////
int analyzecogfile(std::string fileID) {
    if (fileID != "") {
        std::ifstream coginputstream;
        std::string coglocation = "/home/crashlogs/" + fileID;
        coginputstream.open(coglocation);
        if (coginputstream.is_open() == true) {
            std::string cogline;
            std::string cogprefix;
            std::string cogmessage;
            bool completion2g = false;
            int timer67 = 0;
            int timer67max = 5;
            while(completion2g == false) {
                getline(coginputstream, cogline);
                if (cogline != "" && cogmessage.length() >= 6) {
                    cogprefix = cogline.substr(0, 4);
                    cogmessage = cogline.substr(4, cogmessage.length() - 4);
                    
                    // COGPREFIX FOR USERNAMES
                    if (cogprefix == "USE:") {

                    }

                    // COGPREFIX FOR PASSWORDS
                    if (cogprefix == "PAS:") {

                    }

                    // COGPREFIX FOR FOLDER
                    if (cogprefix == "FOL:") {

                    }

                    // COGPREFIX FOR FOLDER
                    if (cogprefix == "FIL:") {

                    }

                    // COGPREFIX FOR FOLDER
                    if (cogprefix == "PUB:") {

                    }

                    // COGPREFIX FOR FOLDER
                    if (cogprefix == "CMD:") {

                    }

                } else {
                    timer67 = timer67 + 1;
                    if (timer67 >= timer67max) {
                        completion2g = true;
                        coginputstream.close();
                        std::string rmoperation = "rm " + coglocation + " >nul: ";
                        int kale = system(rmoperation.c_str());
                        return 0;
                    }
                }
                
            }
        } else {
            logcritical("COG COULD NOT BE OPENED!");
            logcritical(coglocation);
            return 1;
            return 1;
            return 1;
        }
        return 0;
    } else {
        return 255;
    }
    return 1;    
}

int analyzeALLcogfiles() {
    int numberturn = 0;
    bool testsing = false;
    while(testsing == false) {
        int welcoming = analyzecogfile(filenameforcogs[numberturn]);
        if (welcoming != 0 && welcoming != 255) {
            logcritical("AN ERROR OCCURRED IN COG READING!");
            return 1;
            return 1;
            return 1;
        } else {
            numberturn = numberturn + 1;
            cogswaiting = cogswaiting - 1;
        }
        if (cogswaiting == 0 || numberturn >= 255) {
            testsing = true;
        }
    }
    cogswaiting = 0;
    return 0;
}





////////////////////////////////
////////////////////////////////
//// MAIN MAINTENANCE LOOPS ////
//////////////////////////////// 
////////////////////////////////
int maintenancescriptONEHOUR() {




    return 0;
}

int maintenancescriptSIXHOUR() {





    return 0;
}



// THINGS STILL TO DO:
// IP LIST MORE INFO
// MAC LIST
// SEVERITY LIST
// ACPMAC
// CONFIG1 FILE
// USERSTREAM
// PASSSTREAM
// SERVERDUMP
// SERVERFILE
// FOLDERS ACCESSED
// FILES ACCESSED
// CMD RUN FILE
// COG FILE OPERATIONS



////////////////////////////////////////////////////////////////////
//// LOAD THE LIST OF BLOCKED IPs INTO THE SERVER MAIN DATABASE ////
////////////////////////////////////////////////////////////////////
int loadipsafetyintoram() {
    int numberofip = 0;
    bool completion1939 = false;
    int timer2 = 0;
    int timer2max = 5;
    std::ifstream ipsafetystream;
    ipsafetystream.open(blockedipstreamfile);
    std::string nextipaddr = "";
    if (ipsafetystream.is_open() == true) {
        while(completion1939 != true) {
            getline(ipsafetystream, nextipaddr);
            getline(ipsafetystream, nextipaddr);
//            logcritical(nextipaddr);
            numberofip = numberofip + 1;
            ipsafetyRAM->resize(numberofip + 1);
            if (numberofip >= 1000) {
                completion1939 = true;
                logwarning("BLOCKED IP IS >= 1000!");
            }
            if (timer2 >= timer2max) {
                completion1939 = true;
                //loginfo("REACHED END OF LOADING IPSAFETY File!");
            }
            if (nextipaddr == "") {
                timer2 = timer2 + 1;
            } else {
                timer2 = 0;
                ipsafetyRAM[numberofip - 1] = nextipaddr;
            }
        }
        return 0;
    } else {
        logcritical("UNABLE TO OPEN FILE!");
        return 1;
    }
    return 1;
}

////////////////////////////
//// LOAD HTML INTO RAM ////
//////////////////////////// 
int loadmainHTMLintoram() {
    std::string templine;
    std::ifstream htmlmain;
    mainhtmlpayload = "";
    htmlmain.open(mainhtml);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (htmlmain.is_open() == true) {
        while (completionht != true) {
            getline(htmlmain, templine);
            if (templine == "") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            }
            mainhtmlpayload = mainhtmlpayload + templine;
        }
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = mainhtmlpayload.length();
        mainhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + mainhtmlpayload;
        htmlmain.close();
        return 0;
    } else {
        mainhtmlpayload = "500: An Internal Server Error Occurred, Please Try Again Later";
        htmlmain.close();
        return 1;
    }
    mainhtmlpayload = "500: An Internal Server Error Occurred, Please Try Again Later";
    htmlmain.close();
    return 1;
}

int loadpricingHTMLintoram() {
    std::string templine;
    std::ifstream htmlprice;
    pricinghtmlpayload = "";
    htmlprice.open(pricehtml);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (htmlprice.is_open() == true) {
        while (completionht != true) {
            getline(htmlprice, templine);
            if (templine == "") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            }
            pricinghtmlpayload = pricinghtmlpayload + templine;
        }
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = pricinghtmlpayload.length();
        pricinghtmlpayload = httpsuccess + std::to_string(length) + beforepayload + pricinghtmlpayload;
        htmlprice.close();
        return 0;
    } else {
        pricinghtmlpayload = "500: An Internal Server Error Occurred, Please Try Again Later";
        htmlprice.close();
        return 1;
    }
    pricinghtmlpayload = "500: An Internal Server Error Occurred, Please Try Again Later";
    htmlprice.close();
    return 1;
}






////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (80) - MAIN HTML SERVER!! //
////////////////////////////////////////////////////////////
void handleConnections80(int server_fd) { 
    while(runningport80 == true) {
        port80runningstatus = true;
        char buffer[2048] = {0};
        struct sockaddr_in address;
        socklen_t addrlen = sizeof(address);
        int new_socket;
        ssize_t valread;
        std::string hello = "Hello from server";
        

        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // ANTI-CRASH PACKET FLOW CHECK
        if (timers[1] == time(NULL)) {
            packetspam = packetspam + 1;
            if (packetspam >= 10) {
                // STOP CONNECTIONS/ENTER BLOCKING STATE
                waiting230 = true;
                logwarning("LOCKING HTTP PORT FOR NOW (PACKET SPAM)");
                timers[2] = time(NULL);
            }
        } else {
            timers[1] = time(NULL);
            if (packetspam >= 5) {
                packetspam = packetspam -5;
                waiting230 = false;
            } else {
                packetspam = 0;
                waiting230 = false;
            }
        }

        int differenceintime = time(NULL) - timers[2];

        if (differenceintime >= 900) {
            waiting230 = false;
            logwarning("ALLOWING RESTART OF HTTP PROCESS!");
        }

        if (waiting230 == false) {
            // STANDARD OPERATION
            read(new_socket, buffer, 2048);
            sendtolog(buffer);
            int timer89 = 0;
            int timer89max = 5;
            bool completed23 = false;
            if (buffer != "" && sizeof(buffer) >= 7) {
                std::string bufferstring = buffer;
                std::string headerrequest = bufferstring.substr(0,5);
                loginfo(headerrequest);
                
                if (bufferstring.length() >= 7) {
                    // CHANGE HERE FROM GET: / TO GET /
                    if (headerrequest == "GET /") {
                        std::string maindirectory = bufferstring.substr(4,1);
                        logwarning(maindirectory);

                        // MAKE SURE THAT THE ADDRESS IS VALID
                        if (maindirectory == "/") {
                            std::string nextletter = bufferstring.substr(5,2);
                            loginfo(nextletter);

                            // MAIN PAGE
                            if (nextletter == "\n") {
                                int send_res=send(new_socket,mainhtmlpayload.c_str(),mainhtmlpayload.length(),0);
                            }

                            // INDEX.HTML
                            if (nextletter == "in") {
                                //index.html
                                std::string indexfulldictionary = bufferstring.substr(5, 10);
                                if (indexfulldictionary == "index.html") {
                                    int send_res=send(new_socket,mainhtmlpayload.c_str(),mainhtmlpayload.length(),0);
                                }
                            }

                            // PRICING.HTML
                            if (nextletter == "pr") {
                                // pricing.html
                                std::string pricingfulldictionary = bufferstring.substr(5,12);
                                if (pricingfulldictionary == "pricing.html") {
                                    int send_res=send(new_socket,pricinghtmlpayload.c_str(),pricinghtmlpayload.length(),0);
                                }
                            }
                        }
                    } else {
                        int send_res=send(new_socket,httpforbidden.c_str(),httpforbidden.length(),0);
                    }
                } else {
                    int send_res=send(new_socket,httpforbidden.c_str(),httpforbidden.length(),0);
                }
            } else {
                // FUTURE TERMINATE COMMAND
                int send_res=send(new_socket,httpforbidden.c_str(),httpforbidden.length(),0);
            }
            
        } else {
            int send_res=send(new_socket,httpforbidden.c_str(),httpforbidden.length(),0);
        }
    }
    port80runningstatus = false;
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



















int createnetworkport80() {
    int PORT = 80;
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

    // Forcefully attaching socket to the port 80
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

//    int test = writetoipliststrict("HELLO", 0, true, false);
//    test = writetoUSERStream("TEST", true);
//    test = writetoUSERStream("TEST", true);
//    if (test != 0) {
//        logcritical("AN ERROR OCCURRED TRYING TO WRITE TO END OF IPLISTSTRICT");
//    }

//    generateRandomStringHoneyPI();
//    generateRandomStringRouterAPI();
    startuptime = time(NULL);
    startupchecks = startupchecks + timedetector();


    // DETERMINE NETWORK CONNECTIVITY
    sendtologopen("[INFO] - Checking Network Connectivity...");
    int learnt = system("ping -c 5 8.8.8.8 > nul:");
    if (learnt == 0) {
        sendtolog("Done");
    } else {
        sendtolog("ERROR");
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
            sendtolog("Done");
        } else {
            sendtolog("ERROR");
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
            sendtolog("Done");
        } else {
            sendtolog("ERROR");
            logcritical("UNABLE TO UPGRADE SYSTEM!");
            logcritical("This could be potentially dangerous!");
            logcritical("KILLING PROCESS!");
            startupchecks = startupchecks + 1;
            return 1;
            return 1;
            return 1;
        }

    } else {
        sendtolog("disabled");
        logwarning("UNABLE TO CHECK FOR UPDATES! (SYSTEM DISABLED)");
    }




    // VERIFY SERVER FOLDERS ARE OPEN
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






    // OPEN THE SERVER FILES NEW
    std::string versionID;
    std::string currentversionID = "Version: " + honeyversion + "\n";
    std::string compressed;
    int migration = 0;

    // IPLIST STRICT
    sendtologopen("[INFO] - Attempting to Read from IP LIST Strict TXT File...");
    std::ifstream ipliststrict;
    ipliststrict.open(ipliststrictfile);
    if (ipliststrict.is_open() == true) {
        std::getline(ipliststrict, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
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
            if (versionID.substr(0,1) == "V") {
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
            if (versionID.substr(0,1) == "V") {
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
            if (versionID.substr(0,1) == "V") {
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
            if (versionID.substr(0,1) == "V") {
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
            severitylist.open(severitylistfile);
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
    sendtologopen("[INFO] - Attempting to Read from ACPMAC TXT File...");
    std::ifstream acpmac;
    acpmac.open(acpmacfile);
    if (acpmac.is_open() == true) {
        std::getline(acpmac, versionID);
        if (versionID != "") {
                if (versionID.substr(0,1) == "V") {
                    compressed = versionID.substr(9,10);
                } else {
                    compressed = "";
                }            
            } else {
                compressed = "";
            }
            sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - ACPMAC - No Version Found, Writing New Version...");
            acpmac.close();
            std::ofstream acpmac;
            acpmac.open(acpmacfile);
            acpmac.seekp(0);
            acpmac << currentversionID << '\n';
            acpmac.flush();
            if (acpmac.fail() == true) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO ACPMAC");
                if (acpmac.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                acpmac.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different ACPMAC Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("No migration steps detected");
            } else {
                loginfo("ACPMAC Started...");
            }
        }
    } else {
        sendtolog("ERROR!");
        logcritical("UNABLE TO OPEN ACPMAC TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    acpmac.close();
    


    // IPSAFETY INFO
    sendtologopen("[INFO] - Attempting to Read from IPSAFETY File...");
    std::ifstream blockedipstream;
    blockedipstream.open(ipliststandardfile);
    if(blockedipstream.is_open() == true) {
        std::getline(blockedipstream, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - IPSAFETY - No Version Found, Writing New Version...");
            blockedipstream.close();
            std::ofstream blockedipstream;
            blockedipstream.open(blockedipstreamfile);
            blockedipstream.seekp(0);
            blockedipstream << currentversionID << '\n';
            blockedipstream.flush();
            if (blockedipstream.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO IPSAFETY");
                if (blockedipstream.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                blockedipstream.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different IPSAFETY Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("IPSAFETY Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN IPSAFETY TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    blockedipstream.close();



    // CONFIG1 INFO
    sendtologopen("[INFO] - Attempting to Read from SERVERCONFIG1 File...");
    std::ifstream config1;
    config1.open(config1file);
    if(config1.is_open() == true) {
        std::getline(config1, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - SERVERCONFIG1 - No Version Found, Writing New Version...");
            config1.close();
            std::ofstream config1;
            config1.open(config1file);
            config1.seekp(0);
            config1 << currentversionID << '\n';
            config1.flush();
            if (config1.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO SERVERCONFIG1");
                if (config1.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                config1.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different SERVERCONFIG Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("CONFIG1 Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN SERVERCONFIG1 Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    config1.close();



    // USERSTREAM INFO
    sendtologopen("[INFO] - Attempting to Read from USERSTREAM File...");
    std::ifstream userstream;
    userstream.open(userstreamfile);
    if(userstream.is_open() == true) {
        std::getline(userstream, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - USERSTREAM - No Version Found, Writing New Version...");
            userstream.close();
            std::ofstream userstream;
            userstream.open(userstreamfile);
            userstream.seekp(0);
            userstream << currentversionID << '\n';
            userstream.flush();
            if (userstream.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO USERSTREAM");
                if (userstream.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                userstream.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different USERSTREAM Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("USERSTREAM Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN USERSTREAM Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    userstream.close();



    // PASSSTREAM INFO
    sendtologopen("[INFO] - Attempting to Read from PASSSTREAM File...");
    std::ifstream passstream;
    passstream.open(passstreamfile);
    if(passstream.is_open() == true) {
        std::getline(passstream, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - PASSSTREAM - No Version Found, Writing New Version...");
            passstream.close();
            std::ofstream passstream;
            passstream.open(passstreamfile);
            passstream.seekp(0);
            passstream << currentversionID << '\n';
            passstream.flush();
            if (passstream.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO PASSSTREAM");
                if (passstream.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                passstream.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different PASSSTREAM Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("PASSSTREAM Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN PASSSTREAM Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    passstream.close();


    // FOLDERS ACCESSED INFO
    sendtologopen("[INFO] - Attempting to Read from FDACCESSED File...");
    std::ifstream fdaccessed;
    fdaccessed.open(foldersaccessedfile);
    if(fdaccessed.is_open() == true) {
        std::getline(fdaccessed, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - FDACCESSED - No Version Found, Writing New Version...");
            fdaccessed.close();
            std::ofstream fdaccessed;
            fdaccessed.open(foldersaccessedfile);
            fdaccessed.seekp(0);
            fdaccessed << currentversionID << '\n';
            fdaccessed.flush();
            if (fdaccessed.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO FDACCESSED");
                if (fdaccessed.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                fdaccessed.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different FDACCESSED Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("FDACCESSED Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN FDACCESSED Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    fdaccessed.close();


    // FILES ACCESSED INFO
    sendtologopen("[INFO] - Attempting to Read from FLACCESSED File...");
    std::ifstream flaccessed;
    flaccessed.open(filesaccessedfile);
    if(flaccessed.is_open() == true) {
        std::getline(flaccessed, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - FLACCESSED - No Version Found, Writing New Version...");
            flaccessed.close();
            std::ofstream flaccessed;
            flaccessed.open(filesaccessedfile);
            flaccessed.seekp(0);
            flaccessed << currentversionID << '\n';
            flaccessed.flush();
            if (flaccessed.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO FLACCESSED");
                if (flaccessed.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                flaccessed.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different FLACCESSED Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("FLACCESSED Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN FLACCESSED Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    flaccessed.close();


    // CMDS RUN INFO
    sendtologopen("[INFO] - Attempting to Read from CMDRUN File...");
    std::ifstream cmdaccessed;
    cmdaccessed.open(cmdrunfile);
    if(cmdaccessed.is_open() == true) {
        std::getline(cmdaccessed, versionID);
        if (versionID != "") {
            if (versionID.substr(0,1) == "V") {
                compressed = versionID.substr(9,10);
            } else {
                compressed = "";
            }
        } else {
            compressed = "";
        }
        sendtolog("Done");
        if (compressed == "") {
            sendtologopen("[WARNING] - CMDRUN - No Version Found, Writing New Version...");
            cmdaccessed.close();
            std::ofstream cmdaccessed;
            cmdaccessed.open(cmdrunfile);
            cmdaccessed.seekp(0);
            cmdaccessed << currentversionID << '\n';
            cmdaccessed.flush();
            if (cmdaccessed.fail()) {
                sendtolog("ERROR");
                logcritical("AN ERROR OCCURRED WRITING TO CMDRUN");
                if (cmdaccessed.bad() == true) {
                    logcritical("I/O ERROR OCCURRED");
                }
                startupchecks = startupchecks + 1;
                cmdaccessed.close();
            }
            sleep(0.5);
            sendtolog("Done");
        } else {
            if (compressed != honeyversion) {
                migration = migration + 1;
                logwarning("Detected Different CMDRUN Version, Attempting to Update!");
                // MIGRATION STEPS
                logwarning("NO Migration steps detected");
            } else {
                loginfo("CMDRUN Started...");
            }
        }
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO OPEN CMDRUN Standard TXT File!");
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }
    cmdaccessed.close();




    // LOAD IPSAFETY INTO RAM
    sendtologopen("[INFO] - Loading IPSAFETY Into RAM...");
    int ram = loadipsafetyintoram();
    if (ram != 0) {
        sendtolog("ERROR");
        logcritical("AN ERROR OCCURRED LOADING IPSAFETY INTO RAM!");
        startupchecks = startupchecks + 1;
    } else {
        sendtolog("Done");
    }



    // LOAD MAINHTML INTO RAM
    sendtologopen("[INFO] - Loading MAINHTML Into RAM...");
    int ram1 = loadmainHTMLintoram();
    if (ram1 != 0) {
        sendtolog("ERROR");
        logcritical("AN ERROR OCCURRED LOADING MAINHTML INTO RAM!");
        startupchecks = startupchecks + 1;
    } else {
        sendtolog("Done");
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
    int PORT = 80;
    sendtologopen("[INFO] - Opening Server Ports (1/3)");
    port1 = createnetworkport80();
    sendtolog("Done");
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

    sendtolog("Done");
    sleep(2);





    // SERVER PORT LISTEN THREAD (2/3) (11535)
    sendtologopen("[INFO] - Creating server thread on port 11535 listen...");

    sleep(2);
    std::thread acceptingClientsThread2(handle11535Connections, server_fd2);
    acceptingClientsThread2.detach();
    sleep(1);

    sendtolog("Done");




    // SYSTEM STARTED
    sendtologopen("[INFO] - Updating API Token...");


    // FUTURE NETWORK COMMUNICATION TO UPDATE API TOKENS

    sendtolog("future");



    if (serverdumpfilefound == true) {
        loginfo("FUTURE THINGS!");
    }

    // SET TIMERS
    timers[0] = time(NULL);
    timers[1] = time(NULL);
    timers[2] = time(NULL);
    timers[3] = time(NULL);
    timers[4] = time(NULL);
    timers[5] = time(NULL);
    timers[6] = time(NULL);
    timers[7] = time(NULL);
    timers[8] = time(NULL);
    timers[9] = time(NULL);
    timers[10] = time(NULL);

    
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
        sendtologopen("[INFO] - Creating server thread on port 80 listen...");

        sleep(2);
        std::thread acceptingClientsThread(handleConnections80, port1);
        acceptingClientsThread.detach();
        sleep(1);

        sendtolog("Done");



        loginfo("HoneyPi Server has started successfully");

        // NETWORK INFORMATION
        char buffer[BUFFER_SIZE];
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        // MAIN RUNNING LOOP
        while(startupchecks == 0 && encounterederrors == 0) {

            sleep(60);
            loginfo("Running = TRUE...");


            // TIMERS [3] CHECK
            long int differenceintime3 = time(NULL) - timers[3];
            if (differenceintime3 >= 3600) {
                timers[3] = time(NULL);
                maintenancescriptONEHOUR();
            }

            // TIMERS [4] CHECK
            long int differenceintime4 = time(NULL) - timers[4];
            if (differenceintime4 >= 21600) {
                timers[4] = time(NULL);
                maintenancescriptSIXHOUR();
            }

            // TIMERS [5] CHECK
            long int differenceintime5 = time(NULL) - timers[5];
            if (differenceintime5 >= 1800 || cogswaiting >= 100) {
                timers[5] = time(NULL);
                analyzeALLcogfiles();
            }


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