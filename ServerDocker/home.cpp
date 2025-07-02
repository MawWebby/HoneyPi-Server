//////////////////
// Dependencies //
//////////////////
// OTHER FILES TO LINK
#include "globalvariables.h"


// RUNTIME OPTIONS
const bool debug = false;
const bool testing = false;
const bool newserverupdate = true;
const bool EXCEPTION = true;
std::string honeyversion = "0.7.5";
const int heartbeattime = 10;



/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
//// THIS SOFTWARE IS DEVELOPED AND PRODUCED BY MATTHEW WHITWORTH                        ////
////                                                                                     ////
//// DO NOT DUPLICATE, COPY, OR MODIFY THIS SOFTWARE UNLESS WRITTEN BY MATTHEW WHITWORTH ////
////                                                                                     ////
//// ANY FAILURE TO DO SO WILL RESULT IN LEGAL ACTION                                    ////
////                                                                                     ////
//// ANY MONETIZATION THAT IS PRODUCED FROM CODE COPIED FROM MATTHEW                     ////
//// WHITWORTH'S WORK MUST BE COMPENSATED TO THE DEVELOPER                               ////
////                                                                                     ////
//// ANY ACCESS TO THIS CODE WITH THE PERMISSION OF MATTHEW WHITWORTH IS PROHIBITED!     ////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////
/// ATOMIC VARIABLES ///
////////////////////////

// STATUS SIGNALS
std::atomic<int> stopSIGNAL(0);
std::atomic<int> updateSIGNAL(0);
std::atomic<int> statusP80(0);
std::atomic<int> statusP443(0);
std::atomic<int> statusP11829(0);
std::atomic<int> serverErrors(0);
std::atomic<int> serverStarted(0);

// STATUS NUMBERS
std::atomic<long long int> apiRejects(0);
std::atomic<long long int> newConnections(0);
std::atomic<long long int> totalDevicesConnected(0);
std::atomic<long long int> processingErrors(0);
std::atomic<long long int> conversionErrors(0);
std::atomic<long long int> dataEncryptionErrors(0);
std::atomic<long long int> invalidPackets(0);
std::atomic<long long int> analyzedPackets(0);
std::atomic<long long int> clientsDenied(0);
std::atomic<long long int> cogsAnalyzed(0);
std::atomic<long long int> networkErrors(0);
std::atomic<long long int> encryptionchange(0);
std::atomic<long long int> readwriteoperationfail(0);
std::atomic<long long int> entryAdded(0);


// PACKET VARIABLES
std::atomic<int> p80packetslastmin(0);
std::atomic<int> p443packetslastmin(0);
std::atomic<int> p11829packetslastmin(0);
std::atomic<int> p80packetslasthour(0);
std::atomic<int> p443packetslasthour(0);
std::atomic<int> p11829packetslasthour(0);

// LOCK VARIABLES
std::atomic<int> lockP80(0);
std::atomic<int> lockP443(0);
std::atomic<int> lockP11829(0);

// TIMING VARIABLES
std::atomic<long long int> timer0(0);
std::atomic<long long int> timer1(0);
std::atomic<long long int> timer2(0);
std::atomic<long long int> timer3(0);
std::atomic<long long int> timer4(0);
std::atomic<long long int> timer5(0);
std::atomic<long long int> timer6(0);
std::atomic<long long int> timer7(0);
std::atomic<long long int> timer8(0);
std::atomic<long long int> timer9(0);
std::atomic<long long int> timer10(0);
std::atomic<long long int> startuptime(0);
std::atomic<long long int> currenttime(0);
std::atomic<long long int> timesincestartup(0);
std::atomic<int> calculatingtime(0);

// DB LOCKS
std::atomic<int> jsonDBLock(0);

// SERVER ERRORS
std::atomic<int> generalservererrors(0);

// 11829 SERVER PROTECTION LAYER 1
std::map<std::string, int> ip11829;

// 443 SERVER PROTECTION LAYER 1
std::map<std::string, int> ip443;

// VERSION VARIABLES
// HONEYPI - MAIN
std::string latesthoneyPISmainMversion;
std::string latesthoneyPISminorMversion;
std::string latesthoneyPIShotfixMversion;
// HONEYPI - BETA
std::string latesthoneyPIBEMmainversion;
std::string latesthoneyPIBEMminorversion;
std::string latesthoneyPIBEMhotfixversion;
// HONEYPI - TEST
std::string latesthoneyPINIBmainversion;
std::string latesthoneyPINIBminorversion;
std::string latesthoneyPINIBhotfixversion;
// ROUTER - MAIN
std::string latesthoneyROSTmainversion;
std::string latesthoneyROSTminorversion;
std::string latesthoneyROSThotfixversion;
// ROUTER - BETA
std::string latesthoneyROBEmainversion;
std::string latesthoneyROBEminorversion;
std::string latesthoneyROBEhotfixversion;
// ROUTER - TEST
std::string latesthoneyRONImainversion;
std::string latesthoneyRONIminorversion;
std::string latesthoneyRONIhotfixversion;
// SERVER - MAIN
std::string latesthoneyosSERVERMAJOR;
std::string latesthoneyosSERVERMINOR;
std::string latesthoneyosSERVERHOT;


// UPDATE VARIABLES
std::atomic<int> preventupdate(0); // USED IF UPDATE FAILED FOR SOME REASON!


/////////////////
/// VARIABLES ///
/////////////////

// CONSTANTS
const std::string honeymainversion = honeyversion.substr(0,1);
const std::string honeyminorversion = honeyversion.substr(2,1);
const std::string honeyhotfixversion = honeyversion.substr(4,1);




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
bool searchforupdates = true;
std::string updatesforSERVER;   // FIX THIS
std::string updatesforHONEYPI;  // FIX THIS
std::string updatesforHONEYROUTER; // NOT IMPLEMENTED YET
bool updateavailable = false;


// UPDATE VARIABLES
std::string downloadfile; // NOT IMPLEMENTED

// DOCKER VARIABLES
int timesincelastcheckinSSH = 0;
long int lastcheckinSSH = 0;




// NETWORK VARIABLES
int port1, port4;
int server_fd2, new_socket2;
bool packetactive = false;
bool runningnetworksportAPI = true;
std::string ipsafetyRAM[1];
std::string port80clientsIP[1];
int port80clientsIPdata[1];
std::string port11829clientsIP[1];
int port11829clientsIPdata[1];
int packetspam = 0;



// HONEYPOT MAP
std::map <std::string, std::string>honeypotauthtotoken;
std::map <std::string, std::string>previoushoneypotauth;
std::map <std::string, std::string>previoushoneypotauth2;




// SSL INFORMATION
SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}
    





// IP VARIABLES
std::string ipliststandardunencrypt = "";
std::string iplistSTRICTunencrypt = "";
std::string ipliststandardENC = "";
std::string iplistSTRICTENC = "";




// DOCKER COMMANDS
const char* dockerstopcommand = "";
const char* dockerpullnewversioncommand = "";
const char* dockerkillcommand = "";
const char* dockerstopmariadbcommand = "";
const char* dockermovetonewversioncommand = "";
const char* dockerstartnewservercommand = "";
const char* dockerpscommand = "docker ps > nul:";



// FILES 
std::fstream cogfile[256];           // Crashlogs
std::string filenameforcogs[256];    // FILES NAMES FOR COGS (Crashlogs)
std::atomic<int> cogswaiting(0);



// URL LOCATIONS
const std::string updateserverlocation = "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/server.txt";
const std::string updatehoneypilocation = "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/mainversion.txt";
const std::string serverupdatefile = "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/UpdateFiles/version-";
const char* updatehtmlmainweb = "cd /home/pi/honeynvme/current/htmlmain/ && git pull https://github.com/MawWebby/HoneyPi-Website.git current-main > nul:";


// PORT 80 MOVED RESPONSE
const std::string serveraddress = "honeypi.baselinux.net";
const std::string movedresponse = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://" + serveraddress + "/ \r\nContent-Length: 0\r\nConnection: close\r\n\r\n";




// SYSTEM COMMANDS
const char* createnewipliststrictfile = "touch /home/listfiles/ipliststrict.txt";
const char* createnewipliststandardfile = "touch /home/listfiles/ipliststandard.txt";
const char* createnewiplistRAWfile = "touch /home/listfiles/iplistsraw.txt";
const char* createnewiplistsmoreinfo = "touch /home/listfiles/iplistsmoreinfo.txt";
//const char* createnewerrorlogfile = "touch /home/serverdump/errors.txt";




// MIGRATION COMMANDS - PT.1
const char* moveipliststricttonewfile = "mv /home/listfiles/ipliststrict.txt /home/listfiles/ipliststrict2.txt";
const char* moveipliststandardtonewfile = "mv /home/listfiles/ipliststandard.txt /home/listfiles/ipliststandard2.txt";
const char* moveiplistsrawtonewfile = "mv /home/listfiles/iplistsraw.txt /home/listfiles/iplistsraw2.txt";
const char* moveiplistsmoreinfotonewfile = "mv /home/listfiles/iplistsmoreinfo.txt /home/listfiles/iplistsmoreinfo2.txt";



// MIGRATION COMMANDS - PT.2
const char* removeipliststrictfile = "rm /home/listfiles/ipliststrict.txt > nul:";

const char* removetempiplistSTRICTfile = "rm /home/listfiles/ipliststrict2.txt";
const char* removetempiplistSTANDARDfile = "rm /home/listfiles/ipliststandard2.txt";
const char* removetempiplistRAWfile = "rm /home/listfiles/iplistsraw2.txt";
const char* removetempiplistMOREINFOfile = "rm /home/listfiles/iplistsmoreinfo2.txt";



// MIGRATION COMMANDS PT.3
const char* removeoriginaliplistSTRICTfile = "rm /home/listfiles/ipliststrict.txt";


// COG FILE OPERATIONS
const char* createcogfile = "touch /home/crashlogs/";
const char* createcogfileend = ".txt";


// FILE LOCATIONS MAPS
std::map <int, const char*> filelocations = {
    {0, "/home/listfiles/ipliststrict.txt"},
    {1, "/home/listfiles/ipliststandard.txt"},
    {2, "/home/listfiles/iplistraw.txt"},
    {3, "/home/listfiles/iplistsmoreinfo.txt"},
    {4, "/home/listfiles/maclist.txt"},
    {5, "/home/listfiles/severitylist.txt"},
    {6, "/home/listfiles/acpmac.txt"},
    {7, "/home/listfiles/ipsafety.txt"},
    {8, "/home/listfiles/serverconfig1.txt"},
    {9, "/home/listfiles/userstream.txt"},
    {10, "/home/listfiles/passstream.txt"},
    {11, "/home/listfiles/serverdump.txt"},
    {12, "/home/listfiles/log.txt"},
    {13, "/home/listfiles/foldacc.txt"},
    {14, "/home/listfiles/fileacc.txt"},
    {15, "/home/listfiles/cmdrun.txt"},
    {16, "/home/serverdump/errors.txt"},
    {17, "/home/serverdump/ipaccessed.txt"},
    {18, "/home/serverdump/login.txt"},
    {19, "/home/serverdump/serverhistory.txt"},
    {20, "/home/listfiles/extramap.txt"}
};



std::map <int, const char*> tempfilelocations = {
    {0, "/home/listfiles/tempipliststrict.txt"},
    {1, "/home/listfiles/tempipliststandard.txt"},
    {2, "/home/listfiles/tempiplistraw.txt"},
    {3, "/home/listfiles/tempiplistsmoreinfo.txt"},
    {4, "/home/listfiles/tempmaclist.txt"},
    {5, "/home/listfiles/tempseveritylist.txt"},
    {6, "/home/listfiles/tempacpmac.txt"},
    {7, "/home/listfiles/tempipsafety.txt"},
    {8, "/home/listfiles/tempserverconfig1.txt"},
    {9, "/home/listfiles/tempuserstream.txt"},
    {10, "/home/listfiles/temppassstream.txt"},
    {11, "/home/listfiles/tempserverdump.txt"},
    {12, "/home/listfiles/templog.txt"},
    {13, "/home/listfiles/tempfoldacc.txt"},
    {14, "/home/listfiles/tempfileacc.txt"},
    {15, "/home/listfiles/tempcmdrun.txt"},
    {16, "/home/serverdump/temperrors.txt"},
    {17, "/home/serverdump/tempipaccessed.txt"},
    {18, "/home/serverdump/templogin.txt"},
    {19, "/home/serverdump/tempserverhistory.txt"},
    {20, "/home/listfiles/tempextramap.txt"}
};



// FILE FRIENDLY NAME
std::map <int, std::string> filemessages = {
    {0, "IP LIST STRICT"},                  // used
    {1, "IP LIST STANDARD"},                // used
    {2, "IP LIST RAW"},                     // used
    {3, "IP LIST MORE INFO"},               // used
    {4, "MAC LIST"},                        // CHANGED TO FILEEDITS! 
    {5, "SEVERITY LIST"},                   
    {6, "ACCOUNTS / MACS / AND APIs INFO"}, // change to entry history type
    {7, "IP SAFETY"},
    {8, "SERVER CONFIG 1"},
    {9, "USERNAME STREAM"},                 // used
    {10, "PASSWORD STREAM"},                // used
    {11, "SERVER DUMP FILE"},
    {12, "LOG FILE"},                       // used
    {13, "FOLDERS ACCESSED FILE"},          // used
    {14, "FILES ACCESED FILE"},             // used
    {15, "COMMANDS RAN FILE"},              // used
    {16, "ERRORS FILE"},                    
    {17, "IP ACCESSED SERVER FILE"},
    {18, "LOGINS ATTEMPTED ON SERVER FILE"}, // fix this
    {19, "SERVER HISTORY FILE (JSON)"}, // fix this rotating log file
    {20, "EXTRA OPTION MAP"}
};


// FILE VARIABLES
const char* ipliststrictfile = "/home/listfiles/ipliststrict.txt";
const char* ipliststandardfile = "/home/listfiles/ipliststandard.txt";
const char* iplistRAWfile = "/home/listfiles/iplistraw.txt";
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
const char* filearguments = "ios::in | ios::out";
// FIX LATER FOR KEEPALIVE OPERATIONS






// FILE LOCK VARIABLES
bool ipliststrictlock = false;
bool ipliststandardlock = false;
bool ipsafetylock = false;
bool userstreamlock = false;






// ADD SERVER ERRORS!
std::map<int, std::string> addservererrors = {
    {0,""},
    {1,""},
    {2,""},
    {3,""},
    {4,""},
    {5,""},
    {6,""},
    {7,""},
    {8,""},
    {9,""},
    {10,""},
};

// VIEW SERVER ERRORS
std::map<int, std::string> viewservererrors = {
    {0,""},
    {1,""},
    {2,""},
    {3,""},
    {4,""},
    {5,""},
    {6,""},
    {7,""},
    {8,""},
    {9,""},
    {10,""},
};

// CLEAR SERVER ERRORS
std::map<int, std::string> clearservererrors = {
    {0,""},
    {1,""},
    {2,""},
    {3,""},
    {4,""},
    {5,""},
    {6,""},
    {7,""},
    {8,""},
    {9,""},
    {10,""},
};



// ENCRYPT IP VARIABLES! - CRYPT/NUMBERIPADDR/EVALUE
std::map<std::pair<int,int>, std::string> ecryptip = {
    {{0,0}, "a"},
    {{0,1}, "b"},
    {{0,2}, "c"},
    {{0,3}, "d"},
    {{0,4}, "e"},
    {{0,5}, "f"},
    {{0,6}, "g"},
    {{0,7}, "h"},
    {{0,8}, "i"},
    {{0,9}, "j"},
    {{0,10}, "k"},
    {{0,11}, "l"},
    {{0,12}, "m"},
    {{0,13}, "n"},
    {{1,0}, "b"},
    {{1,1}, "c"},
    {{1,2}, "d"},
    {{1,3}, "e"},
    {{1,4}, "f"},
    {{1,5}, "g"},
    {{1,6}, "h"},
    {{1,7}, "i"},
    {{1,8}, "j"},
    {{1,9}, "k"},
    {{1,10}, "l"},
    {{1,11}, "m"},
    {{1,12}, "n"},
    {{1,13}, "o"},
    {{2,0}, "Q"},
    {{2,1}, "W"},
    {{2,2}, "E"},
    {{2,3}, "R"},
    {{2,4}, "T"},
    {{2,5}, "Y"},
    {{2,6}, "U"},
    {{2,7}, "I"},
    {{2,8}, "O"},
    {{2,9}, "P"},
    {{2,10}, "A"},
    {{2,11}, "S"},
    {{2,12}, "D"},
    {{2,13}, "F"},
    {{3,0}, "G"},
    {{3,1}, "H"},
    {{3,2}, "J"},
    {{3,3}, "K"},
    {{3,4}, "L"},
    {{3,5}, "M"},
    {{3,6}, "N"},
    {{3,7}, "B"},
    {{3,8}, "V"},
    {{3,9}, "C"},
    {{3,10}, "P"},
    {{3,11}, "X"},
    {{3,12}, "A"},
    {{3,13}, "S"},
    {{4,0}, "U"},
    {{4,1}, "Y"},
    {{4,2}, "T"},
    {{4,3}, "R"},
    {{4,4}, "E"},
    {{4,5}, "W"},
    {{4,6}, "N"},
    {{4,7}, "B"},
    {{4,8}, "V"},
    {{4,9}, "X"},
    {{4,10}, "L"},
    {{4,11}, "K"},
    {{4,12}, "J"},
    {{4,13}, "H"},
    {{5,0}, "t"},
    {{5,1}, "y"},
    {{5,2}, "u"},
    {{5,3}, "i"},
    {{5,4}, "o"},
    {{5,5}, "p"},
    {{5,6}, "k"},
    {{5,7}, "j"},
    {{5,8}, "h"},
    {{5,9}, "g"},
    {{5,10}, "f"},
    {{5,11}, "d"},
    {{5,12}, "s"},
    {{5,13}, "a"},
    {{6,0}, "o"},
    {{6,1}, "i"},
    {{6,2}, "u"},
    {{6,3}, "y"},
    {{6,4}, "a"},
    {{6,5}, "e"},
    {{6,6}, "b"},
    {{6,7}, "c"},
    {{6,8}, "d"},
    {{6,9}, "e"},
    {{6,10}, "f"},
    {{6,11}, "g"},
    {{6,12}, "h"},
    {{6,13}, "i"},
    {{7,0}, "k"},
    {{7,1}, "l"},
    {{7,2}, "m"},
    {{7,3}, "n"},
    {{7,4}, "o"},
    {{7,5}, "p"},
    {{7,6}, "q"},
    {{7,7}, "r"},
    {{7,8}, "s"},
    {{7,9}, "t"},
    {{7,10}, "u"},
    {{7,11}, "v"},
    {{7,12}, "w"},
    {{7,13}, "x"},
    {{8,0}, "y"},
    {{8,1}, "z"},
    {{8,2}, "A"},
    {{8,3}, "b"},
    {{8,4}, "E"},
    {{8,5}, "G"},
    {{8,6}, "h"},
    {{8,7}, "T"},
    {{8,8}, "u"},
    {{8,9}, "F"},
    {{8,10}, "K"},
    {{8,11}, "J"},
    {{8,12}, "L"},
    {{8,13}, "O"},
    {{9,0}, "Q"},
    {{9,1}, "E"},
    {{9,2}, "T"},
    {{9,3}, "U"},
    {{9,4}, "O"},
    {{9,5}, "K"},
    {{9,6}, "J"},
    {{9,7}, "G"},
    {{9,8}, "F"},
    {{9,9}, "A"},
    {{9,10}, "V"},
    {{9,11}, "B"},
    {{9,12}, "N"},
    {{9,13}, "M"},
    {{10,0}, "U"},
    {{10,1}, "K"},
    {{10,2}, "J"},
    {{10,3}, "Y"},
    {{10,4}, "H"},
    {{10,5}, "G"},
    {{10,6}, "T"},
    {{10,7}, "R"},
    {{10,8}, "F"},
    {{10,9}, "D"},
    {{10,10}, "E"},
    {{10,11}, "S"},
    {{10,12}, "A"},
    {{10,13}, "W"},
    {{11,0}, "1"},
    {{11,1}, "2"},
    {{11,2}, "3"},
    {{11,3}, "4"},
    {{11,4}, "5"},
    {{11,5}, "6"},
    {{11,6}, "7"},
    {{11,7}, "8"},
    {{11,8}, "9"},
    {{11,9}, "a"},
    {{11,10}, "b"},
    {{11,11}, "c"},
    {{11,12}, "d"},
    {{11,13}, "e"},
};





//                               0        1         2         3         4         5         6         7    7
//                              0123456789012345678901234567890123456789012345678901234567890123456789012345
// chactermap for unecnrypt =  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`~[{()}]?%!
//                              ~[{()}]?%!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`
// ACTUAL CHARACTER MAP =      "}]?%!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`~[{()
// UNENCRYPT COGS! - CRYPT/EVALUE/REALVALUE
/*

*/


//////////////////////////////
// DECLARATION OF FUNCTIONS //
//////////////////////////////
int setup();




//////////////////////////////
//// CLOSE SERVER PROCESS ////
//////////////////////////////
void servershutdown() {
    // SERVER SHUTDOWN SCRIPT HERE

    logwarning("SERVER - CALLED TO SHUTDOWN SERVER!", true);

    sleep(15);
    return;
    return;
    return;
    return;
}




///////////////////////////////
//// HANDLE DOCKER SIGNALS ////
///////////////////////////////
void handleSignal(int signal) {
    if (signal == SIGTERM || signal == SIGINT) {
        std::cout << "Received termination signal, shutting down gracefully..." << std::endl;
        stopSIGNAL.store(1);     
    }
}










// CHECK TO SEE IF LATEST HONEYPI VERSION FOR CLIENT DEVICES HAS CHANGED
bool checkhoneypiupdateavailable() {
    loginfo("UPDATES - Checking for HoneyPi Updates...", false);
    checkforhoneypiupdates();
    std::string updatefileinformationhoneypi = updatesforHONEYPI;
    std::string aStd = updatefileinformationhoneypi;
    if (aStd.length() >= 60) {
        std::string header1 = aStd.substr(0, 14);
        if (header1 == "latest.main = ") {
            std::string version1 = aStd.substr(14,5);
            std::string nextcharacter = aStd.substr(19,2);
            latesthoneyPISmainMversion = version1.substr(0,1);
            latesthoneyPISminorMversion = version1.substr(2,1);
            latesthoneyPIShotfixMversion = version1.substr(4,1);
            std::string nextversionheader = aStd.substr(20, 14);
            if (nextversionheader == "latest.beta = ") {
                std::string version2 = aStd.substr(34,5);
                std::string nextcharacter = aStd.substr(40,2);
                latesthoneyPIBEMmainversion = version2.substr(0,1);
                latesthoneyPIBEMminorversion = version2.substr(2,1);
                latesthoneyPIBEMhotfixversion = version2.substr(4,1);
                std::string nextversionheader2 = aStd.substr(40, 14);
                if (nextversionheader2 == "latest.test = ") {
                    std::string version4 = aStd.substr(54,5);
                    latesthoneyPINIBmainversion = version4.substr(0,1);
                    latesthoneyPINIBminorversion = version4.substr(2,1);
                    latesthoneyPINIBhotfixversion = version4.substr(4,1);
                    sendtolog("Done", false);
                    return true;
                } else {
                    sendtolog("ERROR", false);
                    logwarning("INVALID CLIENT_VERSION RECEIVED-3!", true);
                    loginfo(aStd, true);
                    std::cout << aStd.length() << std::endl;
                    return false;
                }
            } else {
                sendtolog("ERROR", false);
                logwarning("INVALID CLIENT_VERSION RECEIVED-2!", true);
                loginfo(aStd, true);
                std::cout << aStd.length() << std::endl;
                return false;
            }
        } else {
            sendtolog("ERROR", false);
            logwarning("INVALID CLIENT_VERSION RECEIVED-1!", true);
            loginfo(aStd, true);
            std::cout << aStd.length() << std::endl;
            return false;
        }
    } else {
        sendtolog("ERROR", false);
        logwarning("UNABLE TO CHECK FOR CLIENT UPDATES!", true);
        loginfo(aStd, true);
        std::cout << aStd.length() << std::endl;
        return false;
    }
    loginfo(aStd, true);
    std::cout << aStd.length() << std::endl;
    return false;
}

// CHECK TO SEE IF VERSION IS DIFFERENT THAN LISTED
bool serverupdateavailable() {
    if (stringtoint(honeymainversion) < stringtoint(latesthoneyosSERVERMAJOR) || stringtoint(honeyminorversion) < stringtoint(latesthoneyosSERVERMINOR) || stringtoint(honeyhotfixversion) < stringtoint(latesthoneyosSERVERHOT)) {
        sendtolog("Done", true);
        loginfo("UPDATES - New Server Update Available!", true);
        return true;
    } else {
        sendtolog("Done", true);
        loginfo("UPDATES - No New Version Found", true);
        return false;
    }
    return false;
}

// CHECK THAT SERVER HAS A VALID HEADER
bool checkserverupdateavailable() {
    loginfo("UPDATES - Checking for Server Updates...", false);
    checkforserverupdates();
    std::string aStd = updatesforSERVER;
    if (aStd.length() >=19) {
        std::string header1 = aStd.substr(0, 14);
        if (header1 == "latest.main = ") {
            std::string version1 = aStd.substr(14,5);
            latesthoneyosSERVERMAJOR = version1.substr(0,1);
            latesthoneyosSERVERMINOR = version1.substr(2,1);
            latesthoneyosSERVERHOT = version1.substr(4,1);
            bool updateavailable23 = serverupdateavailable();
            return updateavailable23;
        } else {
            sendtolog("ERROR", false);
            logwarning("INVALID UPDATE HEADER RECEIVED!", true);
            return false;
        }
    } else {
        sendtolog("ERROR", false);
        logwarning("UNABLE TO CHECK FOR UPDATES!", true);
        return false;
    }
    return false;
}

// CONNECTION TO HOST TO START UPDATING!
void connectiontohostupdate(std::string bashfile) {
    if (bashfile != "" && bashfile.length() >= 200) {
        system(bashfile.c_str());
    }
}

// UPDATE SCRIPT - UPDATE TO NEW SERVER VERSION
int updatetoNewServer() {
    int updatestatus = 0;

    // START PROCESS OF UPDATING
    logwarning("SERVER STARTING TO UPDATE!", true);

    // SMALL DELAY
    sleep(2);

    // SERVER CHECK DOCKER STATUS
    loginfo("Checking for Docker Control...", false);
    int res97 = system(dockerpscommand);
    if (res97 != 0) {
        logcritical("ERROR!", true);
        logcritical("UNABLE TO COMPLETE DOCKER COMMAND!", true);
        logcritical("TERMINATING UPDATE!", true);
        return 1;
    } else {
        sendtolog("done", true);
    }

    // ENDING PORT PROCESSES TO START UPDATE
    loginfo("Closing All Threads...", false);
    updateSIGNAL.store(1);
    sleep(10);
    int p80s = statusP80.load();
    int p443s = statusP443.load();
    int p11829s = statusP11829.load();
    if (p80s == 0 && p443s == 0 && p11829s == 0) {
        sendtolog("Done", true);
    } else {
        logwarning("WARNING", true);
        int updatesig = updateSIGNAL.load();
        if (updatesig == 1) {
            logwarning("PROCESSES DID NOT CLOSE WITHIN TEN SECONDS!", true);
            logwarning("WAITING ANOTHER TEN SECONDS...", false);
            sleep(10);
            p80s = statusP80.load();
            p443s = statusP443.load();
            p11829s = statusP11829.load();
            if (p80s == 0 && p443s == 0 && p11829s == 0) {
                sendtolog("OK", true);
            } else {
                logcritical("ERROR", true);
                logcritical("UNABLE TO STOP PROCESSES!", true);
                updateSIGNAL.store(0);
                logcritical("NOT CONTINUING SERVER UPDATE!", true);
                logcritical("RESTORING SYSTEM TO OPERATIONAL STATUS!", true);
                preventupdate.store(1);
                sleep(2);
                setup();
                return 1;
            }
        } else {
            logcritical("SETTING UPDATESIG = 1 FAILED!", true);
            logcritical("NOT CONTINUING SERVER UPDATE!", true);
            logcritical("RESTORING SYSTEM TO OPERATIONAL STATUS!", true);
            preventupdate.store(1);
            sleep(2);
            setup();
            return 1;
        }
    }

    // CLEAR COG FOLDER
    loginfo("Emptying COGs in DB...", false);
    int res98 = mariadbCLEARCOGS_READ();
    if (res98 != 0) {
        logcritical("ERROR!", true);
        logcritical("UNABLE TO COMPLETE MARIADB COGs!", true);
        logcritical("NOT CONTINUING SERVER UPDATE!", true);
        logcritical("RESTORING SYSTEM TO OPERATIONAL STATUS!", true);
        preventupdate.store(1);
        sleep(2);
        setup();
        return 1;
    } else {
        sendtolog("done", true);
    }

    // DOWNLOAD GITHUB SCRIPT TO UPDATE SERVER
    loginfo("DOWNLOADING SERVER UPDATE...", false);
    std::string mainversion = latesthoneyosSERVERMAJOR;
    std::string minorversion = latesthoneyosSERVERMINOR;
    std::string hotfixversion = latesthoneyosSERVERHOT;
    std::string wgeturl = serverupdatefile + mainversion + "." + minorversion + "." + hotfixversion + ".txt";
    std::string hostcommandtodownload = "wget " + wgeturl;
    sleep(2);
    int downloader = system(wgeturl.c_str());
    if (downloader != 0) {
        sendtolog("ERROR", true);
        logcritical("ERROR OCCURRED ATTEMPTING TO DOWNLOAD UPDATE FILE!", true);
        updatestatus = updatestatus + 1;
    } else {
        sendtolog("Done", true);
    }

    // START SERVER UPDATE FROM GITHUB SCRIPT
    if (updatestatus == 0) {
        loginfo("STARTING SERVER UPDATE...", false);
        std::string bashfile = "version-" + mainversion + "." + minorversion + "." + hotfixversion + ".txt";
        std::thread updateThread(connectiontohostupdate, bashfile);
        updateThread.detach();
        sleep(4);
        sendtolog("DONE", true);
    } else {
        logcritical("NOT CONTINUING SERVER UPDATE!", true);
        logcritical("RESTORING SYSTEM TO OPERATIONAL STATUS!", true);
        preventupdate.store(1);
        sleep(2);
        setup();
        return 1;
    }
    return 255;
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
        sendtolog("", true);
        logcritical("UNABLE TO WRITE TO IP LIST STRICT FILE!", true);
        logcritical("ipliststrictlock = true", true);
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
                    logcritical("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO IPLISTSTRICT", true);
                    if (ipliststrict.bad() == true) {
                        logcritical("I/O ERROR OCCURRED", true);
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
        logcritical("ERROR", true);
        logcritical("UNABLE TO WRITE TO IP LIST STANDARD FILE!", true);
        logcritical("ipliststrictlock = true", true);
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
                    logcritical("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO ipliststandard", true);
                    if (ipliststandard.bad() == true) {
                        logcritical("I/O ERROR OCCURRED", true);
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
        logcritical("ERROR", true);
        logcritical("UNABLE TO WRITE TO IPSAFETY FILE!", true);
        logcritical("ipliststrictlock = true", true);
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
                    logcritical("AN ERROR OCCURRED WRITING TO ipliststandard", true);
                    if (ipsafety.bad() == true) {
                        logcritical("I/O ERROR OCCURRED", true);
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
        logcritical("UNABLE TO WRITE TO USERSTREAM FILE!", true);
        logcritical("ipliststrictlock = true", true);
        return 2;
    } else {
        // CHECK FOR STRING TO ALREADY BE IN DB
        userstreamlock = true;
        int checkcommand = checkstringinUSERStream(username);
        if (checkcommand == -1) {
            logcritical("CHECK OPERATION FAILED!", true);
            return 2;
        } else {
            std::ofstream userstream;
            if (checkcommand == 0) {
                userstream.open(userstreamfile, std::ios::app);
                userstream << username << '\n';
                if (userstream.fail()) {
                    logcritical("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO USERSTREAM", true);
                    if (userstream.bad() == true) {
                        logcritical("I/O ERROR OCCURRED", true);
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
                    logcritical("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO USERSTREAM", true);
                    if (userstream.bad() == true) {
                        logcritical("I/O ERROR OCCURRED", true);
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
                        coginputstream.close();
                        std::string rmoperation = "rm " + coglocation + " >nul: ";
                        system(rmoperation.c_str());
                        return 0;
                    }
                }
                
            }
        } else {
            logcritical("COG COULD NOT BE OPENED AT: " + coglocation, false);
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
            logcritical("AN ERROR OCCURRED IN COG READING!", true);
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



/////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (80) - HTTP REDIRECT!! //
/////////////////////////////////////////////////////////
void handleConnections80() {
    int server_fd23;
    int opt = 1;
    if((server_fd23 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logcritical("SOCKET FAILED (80)", true);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd23, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        logcritical("SETSOCKOPT ERROR (80)", true);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    int PORT23 = 80;
    address.sin_port = htons(PORT23);
    if (bind(server_fd23, (struct sockaddr*)&address, sizeof(address)) < 0) {
        logcritical("BIND FAILED (80)", true);
        close(server_fd23);
        exit(EXIT_FAILURE);
    }
    socklen_t addrlen = sizeof(address);

    if (listen(server_fd23, 10) < 0) {
        logcritical("LISTEN FAILED (80)", true);
        close(server_fd23);
        exit(EXIT_FAILURE);
    }

    fcntl(server_fd23, F_SETFL, O_NONBLOCK);
    sleep(2);

    statusP80.store(1);
    bool http80 = true;

    // WHILE RUNNING LOOP FOR HTTP, WAITING FOR CLIENTS TO CONNECT
    while (http80 == true) {
        int client_fd = accept(server_fd23, (struct sockaddr*)&address, &addrlen);

        if (client_fd < 0) {
            if (client_fd == -1) {
                sleep(1);
                if (stopSIGNAL.load() == true) {
                    http80 = false;
                }
                if (updateSIGNAL.load() == true) {
                    http80 = false;
                }
            } else {
                loginfo("UNABLE TO ACCEPT API CONNECTION", true);
            }
        } else {
            // SEND REDIRECT
            send(client_fd, movedresponse.c_str(), movedresponse.length(), 0);
            close(client_fd);
        }
    }

    // SEND TO SERVER MEM
    loginfo("P80 - Stopped...", true);
    statusP80.store(0);
    close(server_fd23);
    sleep(1);
    return;
}





////////////////////////////////////////
// CREATE NETWORKED CONNECTIONS (443) //
////////////////////////////////////////
int createnetworkport443() {
    int PORT = 443;
    int server_fd3, new_socket3;
    ssize_t valread3;
    struct sockaddr_in address3;
    socklen_t addrlen3 = sizeof(address3);
    std::string hello3 = "Hello from server";
    int opt = 1;

    // SETUP NETWORK PORTS
    if((server_fd3 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logcritical("SOCKET OPTION FAILED! (443)", true);
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 443
    if (setsockopt(server_fd3, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        logcritical("SETSOCKOPT FAILED (443)", true);
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    address3.sin_family = AF_INET;
    address3.sin_addr.s_addr = INADDR_ANY;
    address3.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd3, (struct sockaddr*)&address3, sizeof(address3)) < 0) {
        logcritical("BIND FAILED (443)", true);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd3, 3) < 0) {
        logcritical("LISTEN FAILURE!", true);
        exit(EXIT_FAILURE);
    }

    fcntl(server_fd3, F_SETFL, O_NONBLOCK);

    return server_fd3;
}





////////////////////////////
// THE MAIN SETUP SCRIPTS //
//////////////////////////// 
int setup() {
    // START NEW LOG FILE!
    system("rm /home/serverdump/log.txt");
    system("touch /home/serverdump/log.txt");
    system("rm /home/serverdump/packetlog.txt");
    system("touch /home/serverdump/packetlog.txt");
    sleep(1);


    sendtolog("Hello, World from 2514!", true);
    sendtolog("  _____     _____     ____________      _____      ____  ________________   ____         ____           ______________     ________________  ", true);
    sendtolog("  |   |     |   |    /            `     |   `      |  |  |               |  `  `        /   /           |             `   |               |  ", true);
    sendtolog("  |   |     |   |   /              `    |    `     |  |  |  |¯¯¯¯¯¯¯¯¯¯¯¯    `  `      /   /            |   |¯¯¯¯¯¯`   |  |_____    ______|  ", true);
    sendtolog("  |   |     |   |  /   /¯¯¯¯¯¯¯¯`   `   |     `    |  |  |  |____________     `  `    /   /             |   |______/   |        |   |        ", true);
    sendtolog("  |    ¯¯¯¯¯    |  |   |         |   |  |      `   |  |  |               |     `  `  /   /              |   __________/         |   |        ", true);
    sendtolog("  |    _____    |  |   |         |   |  |   |`  `  |  |  |               |      `  `/   /               |   |                   |   |        ", true);
    sendtolog("  |   |     |   |  |   |         |   |  |   | `  ` |  |  |  |¯¯¯¯¯¯¯¯¯¯¯¯        |     |                |   |                   |   |        ", true);
    sendtolog("  |   |     |   |  |   |         |   |  |   |  `  `|  |  |  |____________        |     |                |   |                   |   |        ", true);
    sendtolog("  |   |     |   |  `   `¯¯¯¯¯¯¯¯¯    /  |   |   `     |  |               |       |     |                |   |             |¯¯¯¯¯     ¯¯¯¯¯|  ", true);
    sendtolog("  |   |     |   |   `               /   |   |    `    |  |               |       |     |                |   |             |               |  ", true);
    sendtolog("  ¯¯¯¯¯     ¯¯¯¯¯    ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯    ¯¯¯¯      `¯¯¯   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯        ¯¯¯¯¯¯                 ¯¯¯¯¯             ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯   ", true);
    sendtolog("SERVER EDITION!", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("Server by Matthew Whitworth (MawWebby)", true);
    sendtolog("Version: " + honeyversion, true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);
    sendtolog("", true);

    // DELAY FOR SYSTEM TO START FURTHER (FIGURE OUT CURRENT TIME)
    sleep(1);



    // PING MARIADB SERVER TO VERIFY CONNECTION
    //startupchecks = startupchecks + mariadb_ping();



    // SET DOCKER CONTAINER OPTIONS
    loginfo("DOCKER  - Setting Container Options...", false);
    signal(SIGTERM, handleSignal);
    signal(SIGINT, handleSignal);
    sendtolog("OK", true);
    sleep(1);




    // DETERMINE NETWORK CONNECTIVITY
    loginfo("NETWORK - Checking Network Connectivity...", false);
    int results = pingnetwork();
    if(results != 0) {
        logcritical("ERROR", true);
        logcritical("STARTING ANYWAY", true);
    } else {
        sendtolog("Done", true);
    }




    // CHECK FOR SYSTEM UPDATES
    bool serverupdate = checkserverupdateavailable();
    if (serverupdate == true) {
        updatedocker();
    }

    bool honeypiupdate = checkhoneypiupdateavailable();
    if(honeypiupdate != true) {
        logwarning("ERROR Checking Updates for HoneyPots! (Non-Volatile)", true);
    }
    sleep(1);




    // VERIFY SERVER FOLDERS ARE OPEN
    loginfo("COG_DIR - Validating COG Directory...", false);
    int testing = system("touch /home/crashlogs/test.txt");
    if (testing != 0) {
        logcritical("ERROR", true);
        logcritical("UNABLE TO WRITE TO CRASHLOGS FOLDER!", true);
        startupchecks = startupchecks + 1;
    } else {
        int working = system("rm /home/crashlogs/test.txt");
        if (working != 0) {
            logcritical("ERROR", true);
            logcritical("UNABLE TO CLEAR CRASHLOGS FOLDER!", true);
            startupchecks = startupchecks + 1;
        } else {
            sendtolog("DONE", true);
        }
    }



    // VALIDATE JSON FILES
    loginfo("JSON_V2 - Validating JSON Files", true);
    int returnedjsons = json_maintenance(true);
    if (returnedjsons == 0 || returnedjsons == 1) {
        loginfo("JSON_V2 - Completed Checks", true);
    } else {
        logwarning("JSON_V2 Returned " + inttostring(returnedjsons), true);
        startupchecks = startupchecks + 1;
    }   




    // CALL NEW HTML MAIN WEB PAGES
    loginfo("HTML    - Updating to Main Head...", false);
    int res256 = system(updatehtmlmainweb);
    if (res256 == 0) {
        sendtolog("DONE", true);
    } else {
        sendtolog("ERROR", true);
        logcritical("HTML    - AN ERROR OCCURRED ATTEMPTING TO UPDATE WITH MAIN HEAD!", true);
    }




    // CHECK STARTUPCHECKS
    if (startupchecks != 0) {
        return 100;
    }




    // OPEN THE SERVER FILES V3
    std::string versionID;
    std::string currentversionID = "Version: " + honeyversion + "\n";
    std::string compressed;
    int migration = 0;
    int filerun = 0;
    int filerunmax = filelocations.size() - 1;
    bool completederr = false;

    // MAIN MIGRATION/CHECK SCRIPT
    while (filerunmax >= filerun && completederr != true) {
        loginfo("FILEV3  - READING " + filemessages[filerun] + "...", false);
        std::ifstream fileinput1;
        fileinput1.open(filelocations[filerun]);
        if (fileinput1.is_open() == true) {
            std::getline(fileinput1, versionID);
            if (versionID != "") {
                if (versionID.substr(0,1) == "V") {
                    compressed = versionID.substr(9,10);
                } else {
                    compressed = "";
                }            
            } else {
                compressed = "";
            }
            sendtolog("Done", true);
            if (compressed == "") {
                sendtolog("", true);
                logwarning(filemessages[filerun] + " - No Version Found, Writing New Version...", false);
                fileinput1.close();
                std::ofstream filecreate1;
                filecreate1.open(ipliststrictfile);
                filecreate1.seekp(0);
                filecreate1 << currentversionID << '\n';
                filecreate1.flush();
                if (filecreate1.fail() == true) {
                    logcritical("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO " + filemessages[filerun], true);
                    if (filecreate1.bad() == true) {
                        logcritical("AN I/O ERROR OCCURRED", true);
                    }
                    startupchecks = startupchecks + 1;
                    filecreate1.close();
                }
                sendtolog("Done", true);
            } else {
                if (compressed != honeyversion) {
                    migration = migration + 1;
                    logwarning("Detected Different " + filemessages[filerun] + " Version, Attempting to Update...", false);
                    fileinput1.close();
                    
                    // MIGRATION STEPS:
                    // PT1 - MOVE IPFILE TO 2
                    // PT2 - CREATE NEW FILE
                    // PT3 - ADD NEW VERSION IDENTIFIER
                    // PT4 - MOVE CONTENTS BACK
                    // PT5 - REMOVE OLD FILE

                    // PART 1  ---
                    std::string movecommand = "mv ";
                    std::string combinedcommandmv = movecommand + filelocations[filerun] + " " + tempfilelocations[filerun];
                    const char* mvchar = combinedcommandmv.c_str();
                    int res249 = system(mvchar);
                    if (res249 == 0) {

                        // PART 2  ---
                        std::string tchcommand = "touch ";
                        std::string tchcombine = tchcommand + filelocations[filerun];
                        const char* tchchar = tchcombine.c_str();
                        int res250 = system(tchchar);
                        if (res250 == 0) {

                            // PART 3  ---
                            std::ofstream filecreate1;
                            filecreate1.open(filelocations[filerun]);
                            if (filecreate1.is_open() == true) {
                                filecreate1 << "Version: " << honeyversion << std::endl << std::endl << std::endl;
                                
                                // PART 4  ---
                                int testing902 = 0;
                                int testing902max = 7;
                                bool completionghb = false;
                                std::ifstream filetempinput;
                                filetempinput.open(tempfilelocations[filerun]);
                                if (filetempinput.is_open() == true) {
                                    std::string templine23;
                                    while (completionghb != true && testing902max >= testing902) {
                                        getline(filetempinput, templine23);
                                        if (templine23 == "") {
                                            testing902 = testing902 + 1;
                                        } else {
                                            if (templine23.length() >= 9) {
                                                std::string subtempline23 = templine23.substr(0,7);
                                                if (subtempline23 != "Version") {
                                                    testing902 = 0;
                                                    filecreate1 << templine23 << std::endl;
                                                }
                                            } else {
                                                testing902 = 0;
                                                filecreate1 << templine23 << std::endl;
                                            }
                                        }
                                        if (testing902 >= testing902max) {
                                            completionghb = true;
                                        }
                                    }
                                    filetempinput.close();

                                    // PT5 ---
                                    std::string rmcommand = "rm ";
                                    std::string rmcombine = rmcommand + tempfilelocations[filerun];
                                    const char* rmchar = rmcombine.c_str();
                                    int res251 = system(rmchar);
                                    if (res251 == 0) {
                                        sendtolog("COMPLETED!", true);
                                        sleep(0.2);
                                    } else {
                                        logcritical("ERROR", true);
                                        logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (5)!", true);
                                        sleep(2);
                                        startupchecks = startupchecks + 1;
                                    }
                                } else {
                                    logcritical("ERROR", true);
                                    logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (4)!", true);
                                    sleep(2);
                                    startupchecks = startupchecks + 1;
                                }
                            } else {
                                logcritical("ERROR", true);
                                logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (3)!", true);
                                sleep(2);
                                startupchecks = startupchecks + 1;
                            }
                        } else {
                            logcritical("ERROR", true);
                            logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (2)!", true);
                            sleep(2);
                            startupchecks = startupchecks + 1;
                        }                    
                    } else {
                        logcritical("ERROR", true);
                        logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (1)!", true);
                        sleep(2);
                        startupchecks = startupchecks + 1;
                    }
                } else {
                    sleep(0.3);
                }
            }
        } else {
            sendtolog("FILE NOT FOUND!", true);
            logwarning("FILEV3  - CREATING NEW " + filemessages[filerun] + " FILE...", false);
            std::string stringcommandlocation = filelocations[filerun];
            std::string filetocreate = "touch " + stringcommandlocation;
            const char* filetocreatechar = filetocreate.c_str();
            system(filetocreatechar);
            std::ofstream filecreate1;
            filecreate1.open(filelocations[filerun]);
            if (filecreate1.is_open() == true) {
                filecreate1 << "Version: " << honeyversion << std::endl << std::endl << std::endl;
                filecreate1.flush();
                if (filecreate1.fail() == true) {
                    sendtolog("ERROR", true);
                    logcritical("AN ERROR OCCURRED WRITING TO " + filemessages[filerun], true);
                    if (filecreate1.bad() == true) {
                        logcritical("AN I/O ERROR OCCURRED", true);
                    }
                    startupchecks = startupchecks + 1;
                    filecreate1.close();
                }
                filecreate1.close();
            } else {
                sendtolog("ERROR", true);
                logcritical("UNABLE TO CREATE NEW" + filemessages[filerun] + "FILE!", true);
                startupchecks = startupchecks + 1;
            }
            sendtolog("Done", true);
        }
        filerun = filerun + 1;
    }



    // LOAD MAINHTML INTO RAM
    loginfo("HTML    - Loading MAINHTML Into RAM...", true);
    int ram1 = loadHTMLINTORAM();
    if (ram1 != 0) {
// FINISH THIS EVENTUALLY - FIX THIS
    }




    // LOAD MAIN SEVERITY CACHE INTO RAM
    loginfo("COMMAND - Loading Severity into RAM...", false);
    std::map<int, std::map<std::string, float>> ram2 = cacheseverity();
    std::map<int, std::map<std::string, float>> errormap;
    errormap[0]["ERROR"] = -1;
    if (ram2 == errormap) {
        logcritical("ERROR", true);
        logcritical("CACHING RETURNED WITH THE ERROR MAP!", true);
        startupchecks = startupchecks + 1;
    } else {
        sendtolog("Done", true);
    }





    // CHECK BEFORE REST OF SERVER STARTUP IF FILES WERE NOT CONFIGURED CORRECTLY
    if (startupchecks != 0 && EXCEPTION == false) {
        logcritical("STARTUP CHECKS DOES NOT EQUAL 0!", true);
        logcritical("STOPPING SERVER!", true);
        return 1;
        return 1;
        return 1;
    }

    



    // START NETWORK PORTS CONFIGURATION
    
    // OPEN NETWORK SERVER PORTS (1/4)
    int PORT = 80;
    loginfo("P80     - Opening Server Ports (1/4)", false);
    std::thread acceptingClientsThread80(handleConnections80);
    acceptingClientsThread80.detach();
    sendtolog("...Done", true);

    // OPEN NETWORK SERVER PORTS (2/4)
    loginfo("P443    - Opening Server Ports (2/4)", false);
    port4 = createnetworkport443();
    sendtolog("...Done", true);

    // OPEN NETWORK SERVER PORTS (3/4)
    PORT = 11829;
    loginfo("P11829  - Opening Server Ports (3/4)", false);
    int server_fd2, new_socket2;
    ssize_t valread2;
    struct sockaddr_in address2;
    socklen_t addrlen2 = sizeof(address2);
    int opt2 = 1;
    
    sleep(1);

    if((server_fd2 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logcritical("P11829  - FAILED TO START SOCKET", true);
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 11829
    if (setsockopt(server_fd2, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt2, sizeof(opt2))) {
        logcritical("P11829  - FAILED TO SET SOCKET OPT", true);
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    address2.sin_family = AF_INET;
    address2.sin_addr.s_addr = INADDR_ANY;
    address2.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd2, (struct sockaddr*)&address2, sizeof(address2)) < 0) {
        logcritical("P11829  - FAILED TO SET BIND", true);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd2, 3) < 0) {
        logcritical("P11829  - FAILED TO START LISTEN", true);
        exit(EXIT_FAILURE);
    }

    fcntl(server_fd2, F_SETFL, O_NONBLOCK);

    sendtolog("...Done", true);





    // SERVER PORT LISTEN THREAD (1/4) (11829)
    loginfo("P11829  - Creating server thread on listen...", false);

    sleep(1);
    std::thread thread11829(handle11829Connections, server_fd2);
    thread11829.detach();

    sendtolog("Done", true);




    // SERVER PORT LISTEN THREAD (443)
    loginfo("P443 - Creating server thread on listen...", false);

    sleep(1);
    std::thread acceptingClientsThread443(handleConnections443, port4);
    acceptingClientsThread443.detach();

    sendtolog("Done", true);




    // CHECK FOR THIS!
    if (serverdumpfilefound == true) {
        logdebug("FUTURE THINGS!", true);
    }


    // SET TIMERS
    timer0.store(time(NULL));
    timer1.store(time(NULL));
    timer2.store(time(NULL));
    timer3.store(time(NULL));
    timer4.store(time(NULL));
    timer5.store(time(NULL));
    timer6.store(time(NULL));
    timer7.store(time(NULL));
    timer8.store(time(NULL));
    timer9.store(time(NULL));
    timer10.store(time(NULL));

    // RETURN CHECKS    
    return startupchecks;
}







int main() {

    // SETUP LOOP
    int startup = setup();
    

    if (startup != 0 && EXCEPTION != true) {
        logcritical("ERROR", true);
        logcritical("STARTUP CHECKS RETURNED EXIT CODE 1", true);
        logcritical("THE SYSTEM COULD NOT CONTINUE!", true);
        logcritical("ALL DOCKER CONTAINERS WILL BE STOPPED", true);

        stopSIGNAL.store(1);

        sleep(10);

        // EXIT AND STOP PROCESSES
        return(10);
        return(10);
        return(10);
    } else {



        loginfo("HoneyPi Server has started successfully", true);
        serverStarted = 1;

        // START ADMIN CONSOLE HERE
        std::thread adminConsole(interactiveTerminal);
        adminConsole.detach();


        
        int delaysignalmax = 1800;
        int delaysignal = delaysignalmax - 15;

        // MAIN RUNNING LOOP
        while(startupchecks == 0 && encounterederrors == 0 && stopSIGNAL.load() == 0 && updateSIGNAL.load() == 0) {

            sleep(1);

            // HEARTBEAT TO LOG
            if (delaysignal >= delaysignalmax) {
                int p80s = statusP80.load();
                int p443s = statusP443.load();
                int p11829s = statusP11829.load();

                // GENERAL STATUS MESSAGE
                if (p80s == true && p443s == true && p11829s == true) {
                    loginfo("running = True", true);
                }

                // CHECK FOR SOMETHING WEIRD
                if (p80s == false) {
                    logwarning("PORT 80 Not Running!", true);
                }
                if (p443s == false) {
                    logwarning("PORT 443 Not Running!", true);
                }
                if (p11829s == false) {
                    logwarning("PORT 11829 Not Running!", true);
                }

                // CHECK FOR LOCKS
                int lockP80s = lockP80.load();
                int lockP443s = lockP443.load();
                int lockP11829s = lockP11829.load();
                if (lockP80s == true) {
                    logwarning("PORT 80 Locked!", true);
                }
                if (lockP443s == true) {
                    logwarning("PORT 443 Locked!", true);
                }
                if (lockP11829s == true) {
                    logwarning("PORT 11829 Locked!", true);
                }
                
                delaysignal = 0;
            } else {
                delaysignal = delaysignal + 1;
            }
            

            // TIMERS [3] CHECK
            long int differenceintime3 = time(NULL) - timer3.load();
            if (differenceintime3 >= 3600) {
                timer3.store(time(NULL));
                maintenancescriptONEHOUR();
            }

            // TIMERS [4] CHECK
            long int differenceintime4 = time(NULL) - timer4.load();
            if (differenceintime4 >= 21600) {
                timer4.store(time(NULL));
                maintenancescriptSIXHOUR();
            }

            // TIMERS [6] CHECK - Rotate Through DB and Remove Packets from IPs
            long int differenceintime6 = time(NULL) - timer6;
            if (differenceintime6 >= 180) {
                timer6.store(time(NULL));
                for (const auto& pair : ip11829) {
                    // std::cout << "IP: " << pair.first << ", Packets: " << pair.second << std::endl;
                    if ((pair.second) > 0 && (pair.second) < 15) {
                        ip11829[pair.first] = pair.second - 1;
                    }
                }
            }
        }

        // ENCOUNTERED ERRORS
        if (encounterederrors != 0) {
            logcritical("ERROR", true);
            logcritical("HONEYPI-SERVER HAS ENCOUNTERED UNRECOVERABLE ERRORS WHILE RUNNING!", true);
            logcritical("HONEYPI-SERVER WILL NOW ATTEMPT A LOG DUMP!", true);
            
            
            // ENCOUNTERED ERRORS LOG DUMP


            


            logcritical("ATTEMPTING TO KILL SERVER!!!", true);
            
            stopSIGNAL.store(1);
            
            sleep(7);
            return 1;
            return 1;
            return 1;
            return 1;
            return 1;
        }

        loginfo("HONEYPI-SERVER WILL NOW ATTEMPT A SAVEFILE DUMP!", true);


        // ENCOUNTERED ERRORS SAVE FILE DUMP


        if (stopSIGNAL.load() != 0) {
            logcritical("Called to Exit!", true);
            sleep(3);
            return 0;
            return 0;
            return 0;
        }
    }

    // SHOULD NEVER REACH HERE SO CLOSE 255
    return 255;
}