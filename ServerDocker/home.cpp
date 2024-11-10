//////////////////
// Dependencies //
//////////////////
#include <arpa/inet.h>              // SOCKET NETWORK OPERATIONS
#include <unistd.h>                 // STANDARD CHARSET!!!
#include <sys/socket.h>             // SOCKET PORT OPERATIONS
#include <string.h>                 // STD::STRINGS
#include <iostream>                 // INPUTS/OUTPUTS OPERATIONS
#include <fstream>                  // FILE STREAMS AND OPERATIONS
#include <thread>                   // MULTI-THREADING SUPPORT
#include <ctime>                    // TIME STRING
#include <random>                   // "RANDOM" STRING GENERATOR
#include <mariadb/conncpp.hpp>      // MARIADB C++ CONNECTOR TO DB
#include <openssl/ssl.h>            // OPENSSL SSL STANDARD LIB
#include <openssl/err.h>            // OPENSSL CATCH EXCEPTIONS AND DEBUGGING FOR MORE DETAIL
#include <curl/curl.h>              // CURL STANDARD LIB FOR UPDATES
#include <curl/easy.h>              // CURL EASY MODE FOR UPDATES
#include <map>                      // STD::MAP VARIABLES AND TABLES
#include <csignal>                  // DOCKER CATCH SIGNALS
#include <fcntl.h>                  // USED FOR NON-BLOCKING SIGNALS!
#include <atomic>


// RUNTIME OPTIONS
const bool debug = false;
const bool testing = false;
const bool newserverupdate = true;
const bool EXCEPTION = true;



/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
//// THIS SOFTWARE IS DEVELOPED AND PRODUCED BY MATTHEW WHITWORTH                        ////
////                                                                                     ////
//// DO NOT DUPLICATE, COPY, OR MODIFY THIS SOFTWARE UNLESS WRITTEN BY MATTHEW WHITWORTH ////
////                                                                                     ////
//// ANY FAILURE TO DO SO WILL RESULT IN LEGAL ACTION                                    ////
////                                                                                     ////
//// ANY MONETIZATION THAT IS PRODUCED FROM CODE COPIED FROM MATTHEW                     ////
//// WHITWORTH'S WORK MUST BE GIVEN TO THE DEVELOPER OR LEGAL ACTION WILL BE USED        ////
////                                                                                     ////
//// ANY ACCESS TO THIS CODE WITH THE PERMISSION OF MATTHEW WHITWORTH IS PROHIBITED!     ////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////



//////////////////////
/// DOCKER SIGNALS ///
//////////////////////
//volatile sig_atomic_t stopSIGNAL = false;
std::atomic<int> stopSIGNAL(0);
std::atomic<int> updateSIGNAL(0);
std::atomic<int> statusP80(0);
std::atomic<int> statusP443(0);
std::atomic<int> statusP11829(0);
std::atomic<int> statusP11830(0);
std::atomic<int> serverErrors(0);


/////////////////
/// VARIABLES ///
/////////////////

// VERSION VARIABLES
const std::string honeyversion = "0.1.0";
const std::string honeymainversion = honeyversion.substr(0,1);
const std::string honeyminorversion = honeyversion.substr(2,1);
const std::string honeyhotfixversion = honeyversion.substr(4,1);
std::string latesthoneymainMversion;
std::string latesthoneyminorMversion;
std::string latesthoneyhotfixMversion;
std::string latesthoneyPIMmainversion;
std::string latesthoneyPIMminorversion;
std::string latesthoneyPIMhotfixversion;
std::string latesthoneyPIBmainversion;
std::string latesthoneyPIBminorversion;
std::string latesthoneyPIBhotfixversion;
std::string latesthoneyPITmainversion;
std::string latesthoneyPITminorversion;
std::string latesthoneyPIThotfixversion;

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
bool searchforupdates = true;
std::string updatefileinformationserver;
std::string updatefileinformationhoneypi;
bool updateavailable = false;


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
int port1, port4;
int server_fd2, new_socket2;
bool packetactive = false;
bool runningnetworksportAPI = true;
std::string ipsafetyRAM[1];
std::string port80clientsIP[1];
int port80clientsIPdata[1];
std::string port11829clientsIP[1];
int port11829clientsIPdata[1];
std::string port11830clientsIP[1];
int port11830clientsIPdata[1];
bool runningport80 = true;
bool port80runningstatus = false;
bool port11829runningstatus = false;
bool port443runningstatus = false;
bool port11830runningstatus = false;
int packetspam = 0;
bool waiting230 = false;
bool api11829 = false;
bool api11830 = false;
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
    



// HTML VARIABLES
std::string mainhtmlpayload;
std::string pricinghtmlpayload;
std::string aboutpayload;
std::string getinfopayload;
std::string getstartedpayload;
std::string signuppayload;
std::string loginpayload;
std::string blogpayload;
std::string accountpayload;
std::string installhtmlpayload;
std::string installscriptSHpayload;
const std::string httpfail = "HTTP/1.0 504 OK\nContent-Type:text/html\nContent-Length: 30\n\n<h1>504: Gateway Time-Out</h1>";
const std::string httpforbidden = "HTTP/1.0 403 OK\nContent-Type:text/html\nContent-Length: 23\n\n<h1>403: Forbidden</h1>";
const std::string httpservererror = "HTTP/1.0 505 OK\nContent-Type:text/html\nContent-Length: 72\n\n<h1>505: An Internal Server Error Occurred, Please Try Again Later.</h1>";
const std::string httpnotfound = "HTTP/1.0 404 OK\nContent-Type:text/html\nContent-Length: 28\n\n<h1>404: Page Not Found</h1>";
const std::string serveraddress = "10.72.91.159";



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
const std::string httpsuccess = "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\nConnection: close\r\nContent-Length: ";
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



// URL LOCATIONS
const std::string updateserverlocation = "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/server.txt";
const std::string updatehoneypilocation = "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/mainversion.txt";
const char* updatehtmlmainweb = "cd /home/pi/honeynvme/current/htmlmain/ && git pull https://github.com/MawWebby/HoneyPi-Website.git current-main > nul:";


// SYSTEM COMMANDS
const char* createnewipliststrictfile = "touch /home/listfiles/ipliststrict.txt";
const char* createnewipliststandardfile = "touch /home/listfiles/ipliststandard.txt";
const char* createnewiplistRAWfile = "touch /home/listfiles/iplistsraw.txt";
const char* createnewiplistsmoreinfo = "touch /home/listfiles/iplistsmoreinfo.txt";
const char* createnewerrorlogfile = "touch /home/serverdump/errors.txt";




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
};



// FILE FRIENDLY NAME
std::map <int, std::string> filemessages = {
    {0, "IP LIST STRICT"},
    {1, "IP LIST STANDARD"},
    {2, "IP LIST RAW"},
    {3, "IP LIST MORE INFO"},
    {4, "MAC LIST"},
    {5, "SEVERITY LIST"},
    {6, "ACCOUNTS / MACS / AND APIs INFO"},
    {7, "IP SAFETY"},
    {8, "SERVER CONFIG 1"},
    {9, "USERNAME STREAM"},
    {10, "PASSWORD STREAM"},
    {11, "SERVER DUMP FILE"},
    {12, "LOG FILE"},
    {13, "FOLDERS ACCESSED FILE"},
    {14, "FILES ACCESED FILE"},
    {15, "COMMANDS RAN FILE"},
    {16, "ERRORS FILE"},
    {17, "IP ACCESSED SERVER FILE"},
    {18, "LOGINS ATTEMPTED ON SERVER FILE"},
    {19, "SERVER HISTORY FILE (JSON)"},
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
const char* mainhtml = "/home/htmlmainweb/index.html";
const char* pricehtml = "/home/htmlmainweb/pricing.html";
const char* bloghtmlfile = "/home/htmlmainweb/blog.html";
const char* loginhtmlfile = "/home/htmlmainweb/login.html";
const char* TOSFreefilefile = "/home/htmlmainweb/TOSFree.html";
const char* TOSProfilefile = "/home/htmlmainweb/TOSPro.html";
const char* TOSEnterprisefile = "/home/htmlmainweb/TOSEnterprise.html";
const char* PrivacyPolicyfile = "/home/htmlmainweb/privacypolicy.html";
const char* getstartedfile = "/home/htmlmainweb/get-started.html";
const char* accountfile = "/home/htmlmainweb/account.html";
const char* installfile = "/home/htmlmainweb/install.html";
const char* installBASH = "/home/htmlmainweb/installscript.sh";
const char* htmlfolder = "/home/htmlmainweb";
const char* signuphtmlfile = "/home/htmlmainweb/signup.html";
const char* configpagehtml = "/home/htmlmainweb/config.html";
const char* errorlog = "/home/serverdump/errors.txt";
const char* filearguments = "ios::in | ios::out";
const char* legendstring = "MyChiefDog79";
// FIX LATER FOR KEEPALIVE OPERATIONS


// DATABASE OPERATIONS
const std::string headerforAPIKeyValid = "SELECT credentialsvalid FROM credentials WHERE honeypiapi = ";
const std::string headerforAPIKeyValid2 = "SELECT credentialsvalid FROM credentials WHERE honeyrouterapi = ";
const std::string headerforAPIKeyValid3 = "SELECT credentialsvalid FROM credentials WHERE honeyrouterapi2 = ";
const std::string headerforAPIKeyValid4 = "SELECT credentialsvalid FROM credentials WHERE honeyrouterapi3 = ";
const std::string headerforAPIKeyValid5 = "SELECT credentialsvalid FROM credentials WHERE honeyrouterapi4 = ";
const std::string headerforAPIKeyValid6 = "SELECT credentialsvalid FROM credentials WHERE honeyrouterapi5 = ";
const std::string insertintocredheader = "INSERT INTO credentials";
const std::string valuestoinsertupe = " (user, pass, email, credentialsvalid) ";
const std::string valuesheader = "VALUES(";
const std::string commaheader = ",";
const std::string updatecredheader = "UPDATE credentials ";
const std::string valuetoinsertSETPIAPI = " SET honeypiapi = ";
const std::string valuetoinsertWHERE = " WHERE user = ";
const std::string mariadbcheckaddrheader = "SELECT blockedip FROM serversecurity WHERE ipaddr = '";
const std::string mariadbaddaddrheader = "INSERT INTO serversecurity (ipaddr, packetsreceived, blockedip, resetattime) VALUES('";
const std::string mariadbblockipaddrheader = "UPDATE serversecurity SET blockedip = 'true' WHERE ipaddr = '";
const std::string mariadbubblockipaddrheader = "UPDATE serversecurity SET blockedip = 'false' WHERE ipaddr = '";
const std::string mariadbreadpacketcountipaddr = "SELECT packetsreceived FROM serversecurity WHERE ipaddr  = '";
const std::string mariadbwritepacketcountipaddr = "UPDATE serversecurity SET packetsreceived = ";
const std::string mariadbwritepacketcountipaddr2 = " WHERE ipaddr = '";
const std::string mariadbmaintenance = "SELECT ipaddr FROM serversecurity";
const std::string mariadbDEVBLOCKFLAG = "SELECT devblockip FROM serversecurity WHERE ipaddr = '";
const std::string mariadbremoveoldipaddr = "DELETE FROM serversecurity WHERE ipaddr = '";
const std::string mariadbpacketheader = "SELECT lastpacket FROM serversecurity WHERE ipaddr = '";
const std::string mariadbuserpiapikey = "SELECT honeypiapi FROM credentials WHERE user = '";
const std::string mariadbverifyuserpassheader = "SELECT pass FROM credentials WHERE user = '";
const std::string mariadbuserverifyvalidheader = "SELECT credentialsvalid FROM credentials WHERE user = '";
const std::string mariadbinsertsessionheader = "UPDATE credentials SET clientsession = '";
const std::string mariadbreademail = "SELECT email FROM credentials WHERE user = '";
const std::string mariadbresetpasswordheader = "UPDATE credentials SET pass = '";
const std::string mariadbremovepiapiheader = "UPDATE credentials SET honeypiapi = '' WHERE user = '";
const std::string mariadbcheckinhoneypiheader = "UPDATE credentials SET honeypilastcheckin = '0' WHERE honeypiapi = '";
const std::string mariadbloadalluserswithsessiontokens = "SELECT user FROM credentials WHERE clientsession != ''";
const std::string mariadbloadalluserswithhoneypis = "SELECT user FROM credentials WHERE honeypilastcheckin != 0";
const std::string mariadbremovesessionID24hours = "UPDATE credentials SET clientsession = '' WHERE user = '";

/*
const std::map <std::pair<int, int>, std::string> mariadbchangeportstatusheader = {
    {{0,0}, "UPDATE serverstatus SET port80running = '0'"},
    {{0,1}, "UPDATE serverstatus SET port80running = '1'"},
    {{1,0}, "UPDATE serverstatus SET port443running = '0'"},
    {{1,1}, "UPDATE serverstatus SET port443running = '1'"},
    {{2,0}, "UPDATE serverstatus SET port11829running = '0'"},
    {{2,1}, "UPDATE serverstatus SET port11829running = '1'"},
    {{3,0}, "UPDATE serverstatus SET port11830running = '0'"},
    {{3,1}, "UPDATE serverstatus SET port11830running = '1'"},
};

const std::map <std::pair<std::string, int>, std::string> mariadbadderrorheader = {
    {{"port80error", 1}, "UPDATE serverstatus SET port80error = poert80error + 1"},
};
*/



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




// ERROR MESSAGES
// SECTOR - SECTOR THAT IS AFFECTED (0-P80; 1-P443; 2-P11829; 3-P11830; 
//                                   4-MARIADB; 5-MARIADBHANDLER; 6-STATUSMARIADB; 7-READ/WRITEERROR(IO/ERROR);
//                                   8-ENCRYPTION_ERROR; 9-COG_STORE_ERROR; 10-API_HANDLER; 11-INTEGRATION; 
//                                   12-PACKET_FILTERING; 13-DNS; 14-BACKUP/STORE; 15-ATTEMPTED_EXPLOIT
//                                   16-UPDATES; )
// SEVERITY - SEVERITY OF INCIDENT
// ACTION - WHAT TO DO WITH SECTOR/SECURITY
//          IGNORE = IGNORE THE ERROR AND CONTINUE
//          NUMBER = ADD NUMBER
//          LOG = LOG INTO ERROR LOG / ADD NUMBER
//          RESTART = ATTEMPT TO RESTART THE MODULE THAT IS NOT WORKING (MARIADB, STATUSMARIADB, INTEGRATION, DNS)
//          LOCK = LOCK MODULE FROM RUNNING (P80, P443, P11829, P11830)
//          SOFT = SOFTCRASH MODULE OR OTHER
//          SOFTALL = SOFTCRASH ALL MODULES/THREADS
//          HARD = HARDCRASH ALL MODULES

// FIX THIS BY ADDING LOCKS TO EACH PORT
std::map<std::pair<int,int>, std::string> servercrash = {
    {{0,0}, "NUMBER"},  // NUMBER = HTTP/HTTPS GENERAL ERROR THAT I DON'T WANT TO CATALOG 50 MILLION TIMES
    {{0,1}, "LOG"},     // LOG = MORE SERIOUS ERROR LIKE BLOCKED IP ADDRESS OR TARGETTED ATTACK
    {{0,2}, "LOCK"},    // LOCK = MORE SERIOUS YET ERROR LIKE DDOS - BLOCK ALL ON ACCESS PORT
    {{0,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{1,0}, "NUMBER"},  // NUMBER = HTTPS GENERAL ERROR THAT I DON'T WANT TO CATALOG 50 MILLION TIMES
    {{1,1}, "LOG"},     // LOG = MORE SERIOUS ERROR LIKE BLOCKING A PARTICULAR IP THAT WOULD BE NICE TO HAVE IN THE LOG
    {{1,2}, "LOCK"},    // LOCK = MORE SERIOUS YET AS BLCOKING PORT TEMPORARILY AND SENDING FAILED REQUESTS TO EACH IMPACTED CLIENT
    {{1,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{2,0}, "NUMBER"},  // NUMBER = 
    {{2,1}, "LOG"},     // LOG = 
    {{2,2}, "LOCK"},    // LOCK = 
    {{2,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{3,0}, "NUMBER"},  // NUMBER = 
    {{3,1}, "LOG"},     // LOG = 
    {{3,2}, "LOCK"},    // LOCK = 
    {{3,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{4,0}, "NUMBER"},  // NUMBER = ONLY INCLUDE NUMBERS FOR MARIADB GENERAL ERRORS LIKE NO USER FOUND
    {{4,1}, "LOG"},     // LOG = LOG ERRORS INVOLVING INVALID CREDENTIALS OR SOMETHING LIKE THAT FOR API
    {{4,2}, "SOFT"},    // SOFT = SOFT MODULE RESET MARIADB HANDLER
    {{4,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{5,0}, "NUMBER"},  // NUMBER = 
    {{5,1}, "LOG"},     // LOG = 
    {{5,2}, "SOFTALL"}, // SOFTALL = 
    {{5,3}, "HARD"},    // HARD = 

    {{6,0}, "IGNORE"},  // IGNORE = JUST IGNORE THE ERROR AND CONTINUE
    {{6,1}, "IGNORE"},  // IGNORE = JUST IGNORE THE ERROR AND CONTINUE
    {{6,2}, "LOG"},     // LOG = LOG THE ERROR OF THE STATUS, BUT OTHERWISE DON'T DO ANYTHING
    {{6,3}, "HARD"},    // APPARENTLY THE ERROR IS SERIOUS ENOUGH WHERE IT NEEDS TO LOCK THE SERVER AND CRASH EVERYTHING

    {{7,0}, "LOG"},     // LOG - LOG THE FILE I/O OR OTHER ERROR
    {{7,1}, "SOFT"},    // SOFT = SOFT RESET THE FILE WRITING MODULE
    {{7,2}, "HARD"},    // HARD = UNABLE TO WRITE ANYTHING TO FILE SYSTEM - PREVENT LOSS OF DATA IMMEDIATELY!
    {{7,3}, "HARD"},    // HARD = SUSPECTED INTRUSION - IMMEDIATELY SAVE SERVER STATE AND HARD CRASH IMMEDIATELY

    {{8,0}, "NUMBER"},
    {{8,1}, "NUMBER"},
    {{8,2}, "LOG"},
    {{8,3}, "SOFT"},

    {{9,0}, "LOG"},
    {{9,1}, "LOG"},
    {{9,2}, "SOFTALL"},
    {{9,3}, "HARD"},

    {{10,0}, "NUMBER"},
    {{10,1}, "LOG"},
    {{10,2}, "LOCK"},
    {{10,3}, "HARD"},

    {{11,0}, "NUMBER"},
    {{11,1}, "LOG"},
    {{11,2}, "LOG"},
    {{11,3}, "SOFT"},

    {{12,0}, "NUMBER"},
    {{12,1}, "LOG"},
    {{12,2}, "SOFT"},
    {{12,3}, "HARD"},

    {{13,0}, "NUMBER"},
    {{13,1}, "LOG"},
    {{13,2}, "SOFT"},
    {{13,3}, "HARD"},

    {{14,0}, "LOG"},
    {{14,1}, "RESTART"},
    {{14,2}, "SOFTALL"},
    {{14,3}, "HARD"},

    {{15,0}, "RESTART"},
    {{15,1}, "SOFTALL"},
    {{15,2}, "HARD"},
    {{15,3}, "HARD"},

    {{16,0}, "NUMBER"},
    {{16,1}, "NUMBER"},
    {{16,2}, "LOG"},
    {{16,3}, "UPDATES"},
};

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

std::string charactermap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";




//                              0        1         2         3         4         5         6         7     7
//                              1234567890123456789012345678901234567890123456789012345678901234567890123456
// chactermap for unecnrypt =  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`~[{()}]?%!"
//                              ~[{()}]?%!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`
// ACTUAL CHARACTER MAP =      "}]?%!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789;:/`~[{()"
// UNENCRYPT COGS! - CRYPT/EVALUE/REALVALUE
std::map<std::pair<int, std::string>, std::string> uecryptcog = {
    {{0, "}"}, "A"},
    {{0, "]"}, "B"},
    {{0, "?"}, "C"},
    {{0, "%"}, "D"},
    {{0, "!"}, "E"},
    {{0, "A"}, "F"},
    {{0, "B"}, "G"},
    {{0, "C"}, "H"},
    {{0, "D"}, "I"},
    {{0, "E"}, "J"},
    {{0, "F"}, "K"},
    {{0, "G"}, "L"},
    {{0, "H"}, "M"},
    {{0, "I"}, "N"},
    {{0, "J"}, "O"},
    {{0, "K"}, "P"},
    {{0, "L"}, "Q"},
    {{0, "M"}, "R"},
    {{0, "N"}, "S"},
    {{0, "O"}, "T"},
    {{0, "P"}, "U"},
    {{0, "Q"}, "V"},
    {{0, "R"}, "W"},
    {{0, "S"}, "X"},
    {{0, "T"}, "Y"},
    {{0, "U"}, "Z"},
    {{0, "V"}, "a"},
    {{0, "W"}, "b"},
    {{0, "X"}, "c"},
    {{0, "Y"}, "d"},
    {{0, "Z"}, "e"},
    {{0, "a"}, "f"},
    {{0, "b"}, "g"},
    {{0, "c"}, "h"},
    {{0, "d"}, "i"},
    {{0, "e"}, "j"},
    {{0, "f"}, "k"},
    {{0, "g"}, "l"},
    {{0, "h"}, "m"},
    {{0, "i"}, "n"},
    {{0, "j"}, "o"},
    {{0, "k"}, "p"},
    {{0, "l"}, "q"},
    {{0, "m"}, "r"},
    {{0, "n"}, "s"},
    {{0, "o"}, "t"},
    {{0, "p"}, "u"},
    {{0, "q"}, "v"},
    {{0, "r"}, "w"},
    {{0, "s"}, "x"},
    {{0, "t"}, "y"},
    {{0, "u"}, "z"},
    {{0, "v"}, "0"},
    {{0, "w"}, "1"},
    {{0, "x"}, "2"},
    {{0, "y"}, "3"},
    {{0, "z"}, "4"},
    {{0, "0"}, "5"},
    {{0, "1"}, "6"},
    {{0, "2"}, "7"},
    {{0, "3"}, "8"},
    {{0, "4"}, "9"},
    {{0, "5"}, ";"},
    {{0, "6"}, ":"},
    {{0, "7"}, "/"},
    {{0, "8"}, "`"},
    {{0, "9"}, "~"},
    {{0, ";"}, "["},
    {{0, ":"}, "{"},
    {{0, "/"}, "("},
    {{0, "`"}, "}"},
    {{0, "~"}, "}"},
    {{0, "["}, "]"},
    {{0, "{"}, "?"},
    {{0, "("}, "%"},
    {{0, ")"}, "!"},
    {{1, "}"}, "!"},
    {{1, "]"}, "A"},
    {{1, "?"}, "B"},
    {{1, "%"}, "C"},
    {{1, "!"}, "D"},
    {{1, "A"}, "E"},
    {{1, "B"}, "F"},
    {{1, "C"}, "G"},
    {{1, "D"}, "H"},
    {{1, "E"}, "I"},
    {{1, "F"}, "J"},
    {{1, "G"}, "K"},
    {{1, "H"}, "L"},
    {{1, "I"}, "M"},
    {{1, "J"}, "N"},
    {{1, "K"}, "O"},
    {{1, "L"}, "P"},
    {{1, "M"}, "Q"},
    {{1, "N"}, "R"},
    {{1, "O"}, "S"},
    {{1, "P"}, "T"},
    {{1, "Q"}, "U"},
    {{1, "R"}, "V"},
    {{1, "S"}, "W"},
    {{1, "T"}, "X"},
    {{1, "U"}, "Y"},
    {{1, "V"}, "Z"},
    {{1, "W"}, "a"},
    {{1, "X"}, "b"},
    {{1, "Y"}, "c"},
    {{1, "Z"}, "d"},
    {{1, "a"}, "e"},
    {{1, "b"}, "f"},
    {{1, "c"}, "g"},
    {{1, "d"}, "h"},
    {{1, "e"}, "i"},
    {{1, "f"}, "j"},
    {{1, "g"}, "k"},
    {{1, "h"}, "l"},
    {{1, "i"}, "m"},
    {{1, "j"}, "n"},
    {{1, "k"}, "o"},
    {{1, "l"}, "p"},
    {{1, "m"}, "q"},
    {{1, "n"}, "r"},
    {{1, "o"}, "s"},
    {{1, "p"}, "t"},
    {{1, "q"}, "u"},
    {{1, "r"}, "v"},
    {{1, "s"}, "w"},
    {{1, "t"}, "x"},
    {{1, "u"}, "y"},
    {{1, "v"}, "z"},
    {{1, "w"}, "0"},
    {{1, "x"}, "1"},
    {{1, "y"}, "2"},
    {{1, "z"}, "3"},
    {{1, "0"}, "4"},
    {{1, "1"}, "5"},
    {{1, "2"}, "6"},
    {{1, "3"}, "7"},
    {{1, "4"}, "8"},
    {{1, "5"}, "9"},
    {{1, "6"}, ";"},
    {{1, "7"}, ":"},
    {{1, "8"}, "/"},
    {{1, "9"}, "`"},
    {{1, ";"}, "~"},
    {{1, ":"}, "["},
    {{1, "/"}, "{"},
    {{1, "`"}, "("},
    {{1, "~"}, ")"},
    {{1, "["}, "}"},
    {{1, "{"}, "]"},
    {{1, "("}, "?"},
    {{1, ")"}, "%"},
    {{2, "}"}, "%"},
    {{2, "]"}, "!"},
    {{2, "?"}, "A"},
    {{2, "%"}, "B"},
    {{2, "!"}, "C"},
    {{2, "A"}, "D"},
    {{2, "B"}, "E"},
    {{2, "C"}, "F"},
    {{2, "D"}, "G"},
    {{2, "E"}, "H"},
    {{2, "F"}, "I"},
    {{2, "G"}, "J"},
    {{2, "H"}, "K"},
    {{2, "I"}, "L"},
    {{2, "J"}, "M"},
    {{2, "K"}, "N"},
    {{2, "L"}, "O"},
    {{2, "M"}, "P"},
    {{2, "N"}, "Q"},
    {{2, "O"}, "R"},
    {{2, "P"}, "S"},
    {{2, "Q"}, "T"},
    {{2, "R"}, "U"},
    {{2, "S"}, "V"},
    {{2, "T"}, "W"},
    {{2, "U"}, "X"},
    {{2, "V"}, "Y"},
    {{2, "W"}, "Z"},
    {{2, "X"}, "a"},
    {{2, "Y"}, "b"},
    {{2, "Z"}, "c"},
    {{2, "a"}, "d"},
    {{2, "b"}, "e"},
    {{2, "c"}, "f"},
    {{2, "d"}, "g"},
    {{2, "e"}, "h"},
    {{2, "f"}, "i"},
    {{2, "g"}, "j"},
    {{2, "h"}, "k"},
    {{2, "i"}, "l"},
    {{2, "j"}, "m"},
    {{2, "k"}, "n"},
    {{2, "l"}, "o"},
    {{2, "m"}, "p"},
    {{2, "n"}, "q"},
    {{2, "o"}, "r"},
    {{2, "p"}, "s"},
    {{2, "q"}, "t"},
    {{2, "r"}, "u"},
    {{2, "s"}, "v"},
    {{2, "t"}, "w"},
    {{2, "u"}, "x"},
    {{2, "v"}, "y"},
    {{2, "w"}, "z"},
    {{2, "x"}, "0"},
    {{2, "y"}, "1"},
    {{2, "z"}, "2"},
    {{2, "0"}, "3"},
    {{2, "1"}, "4"},
    {{2, "2"}, "5"},
    {{2, "3"}, "6"},
    {{2, "4"}, "7"},
    {{2, "5"}, "8"},
    {{2, "6"}, "9"},
    {{2, "7"}, ";"},
    {{2, "8"}, ":"},
    {{2, "9"}, "/"},
    {{2, ";"}, "`"},
    {{2, ":"}, "~"},
    {{2, "/"}, "["},
    {{2, "`"}, "{"},
    {{2, "~"}, "("},
    {{2, "["}, ")"},
    {{2, "{"}, "}"},
    {{2, "("}, "]"},
    {{2, ")"}, "?"},
    {{3, "}"}, "?"},
    {{3, "]"}, "%"},
    {{3, "?"}, "!"},
    {{3, "%"}, "A"},
    {{3, "!"}, "B"},
    {{3, "A"}, "C"},
    {{3, "B"}, "D"},
    {{3, "C"}, "E"},
    {{3, "D"}, "F"},
    {{3, "E"}, "G"},
    {{3, "F"}, "H"},
    {{3, "G"}, "I"},
    {{3, "H"}, "J"},
    {{3, "I"}, "K"},
    {{3, "J"}, "L"},
    {{3, "K"}, "M"},
    {{3, "L"}, "N"},
    {{3, "M"}, "O"},
    {{3, "N"}, "P"},
    {{3, "O"}, "Q"},
    {{3, "P"}, "R"},
    {{3, "Q"}, "S"},
    {{3, "R"}, "T"},
    {{3, "S"}, "U"},
    {{3, "T"}, "V"},
    {{3, "U"}, "W"},
    {{3, "V"}, "X"},
    {{3, "W"}, "Y"},
    {{3, "X"}, "Z"},
    {{3, "Y"}, "a"},
    {{3, "Z"}, "b"},
    {{3, "a"}, "c"},
    {{3, "b"}, "d"},
    {{3, "c"}, "e"},
    {{3, "d"}, "f"},
    {{3, "e"}, "g"},
    {{3, "f"}, "h"},
    {{3, "g"}, "i"},
    {{3, "h"}, "j"},
    {{3, "i"}, "k"},
    {{3, "j"}, "l"},
    {{3, "k"}, "m"},
    {{3, "l"}, "n"},
    {{3, "m"}, "o"},
    {{3, "n"}, "p"},
    {{3, "o"}, "q"},
    {{3, "p"}, "r"},
    {{3, "q"}, "s"},
    {{3, "r"}, "t"},
    {{3, "s"}, "u"},
    {{3, "t"}, "v"},
    {{3, "u"}, "w"},
    {{3, "v"}, "x"},
    {{3, "w"}, "y"},
    {{3, "x"}, "z"},
    {{3, "y"}, "0"},
    {{3, "z"}, "1"},
    {{3, "0"}, "2"},
    {{3, "1"}, "3"},
    {{3, "2"}, "4"},
    {{3, "3"}, "5"},
    {{3, "4"}, "6"},
    {{3, "5"}, "7"},
    {{3, "6"}, "8"},
    {{3, "7"}, "9"},
    {{3, "8"}, ";"},
    {{3, "9"}, ":"},
    {{3, ";"}, "/"},
    {{3, ":"}, "`"},
    {{3, "/"}, "~"},
    {{3, "`"}, "["},
    {{3, "~"}, "{"},
    {{3, "["}, "("},
    {{3, "{"}, ")"},
    {{3, "("}, "}"},
    {{3, ")"}, "]"},
    {{4, "}"}, "]"},
    {{4, "]"}, "?"},
    {{4, "?"}, "%"},
    {{4, "%"}, "!"},
    {{4, "!"}, "A"},
    {{4, "A"}, "B"},
    {{4, "B"}, "C"},
    {{4, "C"}, "D"},
    {{4, "D"}, "E"},
    {{4, "E"}, "F"},
    {{4, "F"}, "G"},
    {{4, "G"}, "H"},
    {{4, "H"}, "I"},
    {{4, "I"}, "J"},
    {{4, "J"}, "K"},
    {{4, "K"}, "L"},
    {{4, "L"}, "M"},
    {{4, "M"}, "N"},
    {{4, "N"}, "O"},
    {{4, "O"}, "P"},
    {{4, "P"}, "Q"},
    {{4, "Q"}, "R"},
    {{4, "R"}, "S"},
    {{4, "S"}, "T"},
    {{4, "T"}, "U"},
    {{4, "U"}, "V"},
    {{4, "V"}, "W"},
    {{4, "W"}, "X"},
    {{4, "X"}, "Y"},
    {{4, "Y"}, "Z"},
    {{4, "Z"}, "a"},
    {{4, "a"}, "b"},
    {{4, "b"}, "c"},
    {{4, "c"}, "d"},
    {{4, "d"}, "e"},
    {{4, "e"}, "f"},
    {{4, "f"}, "g"},
    {{4, "g"}, "h"},
    {{4, "h"}, "i"},
    {{4, "i"}, "j"},
    {{4, "j"}, "k"},
    {{4, "k"}, "l"},
    {{4, "l"}, "m"},
    {{4, "m"}, "n"},
    {{4, "n"}, "o"},
    {{4, "o"}, "p"},
    {{4, "p"}, "q"},
    {{4, "q"}, "r"},
    {{4, "r"}, "s"},
    {{4, "s"}, "t"},
    {{4, "t"}, "u"},
    {{4, "u"}, "v"},
    {{4, "v"}, "w"},
    {{4, "w"}, "x"},
    {{4, "x"}, "y"},
    {{4, "y"}, "z"},
    {{4, "z"}, "0"},
    {{4, "0"}, "1"},
    {{4, "1"}, "2"},
    {{4, "2"}, "3"},
    {{4, "3"}, "4"},
    {{4, "4"}, "5"},
    {{4, "5"}, "6"},
    {{4, "6"}, "7"},
    {{4, "7"}, "8"},
    {{4, "8"}, "9"},
    {{4, "9"}, ";"},
    {{4, ";"}, ":"},
    {{4, ":"}, "/"},
    {{4, "/"}, "`"},
    {{4, "`"}, "~"},
    {{4, "~"}, "["},
    {{4, "["}, "{"},
    {{4, "{"}, "("},
    {{4, "("}, ")"},
    {{4, ")"}, "}"},
    {{5, "}"}, "}"},
    {{5, "]"}, "]"},
    {{5, "?"}, "?"},
    {{5, "%"}, "%"},
    {{5, "!"}, "!"},
    {{5, "A"}, "A"},
    {{5, "B"}, "B"},
    {{5, "C"}, "C"},
    {{5, "D"}, "D"},
    {{5, "E"}, "E"},
    {{5, "F"}, "F"},
    {{5, "G"}, "G"},
    {{5, "H"}, "H"},
    {{5, "I"}, "I"},
    {{5, "J"}, "J"},
    {{5, "K"}, "K"},
    {{5, "L"}, "L"},
    {{5, "M"}, "M"},
    {{5, "N"}, "N"},
    {{5, "O"}, "O"},
    {{5, "P"}, "P"},
    {{5, "Q"}, "Q"},
    {{5, "R"}, "R"},
    {{5, "S"}, "S"},
    {{5, "T"}, "T"},
    {{5, "U"}, "U"},
    {{5, "V"}, "V"},
    {{5, "W"}, "W"},
    {{5, "X"}, "X"},
    {{5, "Y"}, "Y"},
    {{5, "Z"}, "Z"},
    {{5, "a"}, "a"},
    {{5, "b"}, "b"},
    {{5, "c"}, "c"},
    {{0, "d"}, "d"},
    {{5, "e"}, "e"},
    {{5, "f"}, "f"},
    {{5, "g"}, "g"},
    {{5, "h"}, "h"},
    {{5, "i"}, "i"},
    {{5, "j"}, "k"},
    {{5, "k"}, "l"},
    {{5, "l"}, "l"},
    {{5, "m"}, "m"},
    {{5, "n"}, "n"},
    {{5, "o"}, "o"},
    {{5, "p"}, "p"},
    {{5, "q"}, "q"},
    {{5, "r"}, "r"},
    {{5, "s"}, "s"},
    {{5, "t"}, "t"},
    {{5, "u"}, "u"},
    {{5, "v"}, "v"},
    {{5, "w"}, "w"},
    {{5, "x"}, "x"},
    {{5, "y"}, "y"},
    {{5, "z"}, "z"},
    {{5, "0"}, "0"},
    {{5, "1"}, "1"},
    {{5, "2"}, "2"},
    {{5, "3"}, "3"},
    {{5, "4"}, "4"},
    {{5, "5"}, "5"},
    {{5, "6"}, "6"},
    {{5, "7"}, "7"},
    {{5, "8"}, "8"},
    {{5, "9"}, "9"},
    {{5, ";"}, ";"},
    {{5, ":"}, ":"},
    {{5, "/"}, "/"},
    {{5, "`"}, "`"},
    {{5, "~"}, "~"},
    {{5, "["}, "["},
    {{5, "{"}, "{"},
    {{5, "("}, "("},
    {{5, ")"}, "}"},
    {{6, "}"}, ")"},
    {{6, "]"}, "}"},
    {{6, "?"}, "]"},
    {{6, "%"}, "?"},
    {{6, "!"}, "%"},
    {{6, "A"}, "!"},
    {{6, "B"}, "A"},
    {{6, "C"}, "B"},
    {{6, "D"}, "C"},
    {{6, "E"}, "D"},
    {{6, "F"}, "E"},
    {{6, "G"}, "F"},
    {{6, "H"}, "G"},
    {{6, "I"}, "H"},
    {{6, "J"}, "I"},
    {{6, "K"}, "J"},
    {{6, "L"}, "K"},
    {{6, "M"}, "L"},
    {{6, "N"}, "M"},
    {{6, "O"}, "N"},
    {{6, "P"}, "O"},
    {{6, "Q"}, "P"},
    {{6, "R"}, "Q"},
    {{6, "S"}, "R"},
    {{6, "T"}, "S"},
    {{6, "U"}, "T"},
    {{6, "V"}, "U"},
    {{6, "W"}, "V"},
    {{6, "X"}, "W"},
    {{6, "Y"}, "X"},
    {{6, "Z"}, "Y"},
    {{6, "a"}, "Z"},
    {{6, "b"}, "a"},
    {{6, "c"}, "b"},
    {{6, "d"}, "c"},
    {{6, "e"}, "d"},
    {{6, "f"}, "e"},
    {{6, "g"}, "f"},
    {{6, "h"}, "g"},
    {{6, "i"}, "h"},
    {{6, "j"}, "i"},
    {{6, "k"}, "j"},
    {{6, "l"}, "k"},
    {{6, "m"}, "l"},
    {{6, "n"}, "m"},
    {{6, "o"}, "n"},
    {{6, "p"}, "o"},
    {{6, "q"}, "p"},
    {{6, "r"}, "q"},
    {{6, "s"}, "r"},
    {{6, "t"}, "s"},
    {{6, "u"}, "t"},
    {{6, "v"}, "u"},
    {{6, "w"}, "v"},
    {{6, "x"}, "w"},
    {{6, "y"}, "x"},
    {{6, "z"}, "y"},
    {{6, "0"}, "z"},
    {{6, "1"}, "0"},
    {{6, "2"}, "1"},
    {{6, "3"}, "2"},
    {{6, "4"}, "3"},
    {{6, "5"}, "4"},
    {{6, "6"}, "5"},
    {{6, "7"}, "6"},
    {{6, "8"}, "7"},
    {{6, "9"}, "8"},
    {{6, ";"}, "9"},
    {{6, ":"}, ";"},
    {{6, "/"}, ":"},
    {{6, "`"}, "/"},
    {{6, "~"}, "`"},
    {{6, "["}, "~"},
    {{6, "{"}, "["},
    {{6, "("}, "{"},
    {{6, ")"}, "("},
    {{7, "}"}, "("},
    {{7, "]"}, ")"},
    {{7, "?"}, "}"},
    {{7, "%"}, "]"},
    {{7, "!"}, "?"},
    {{7, "A"}, "%"},
    {{7, "B"}, "!"},
    {{7, "C"}, "A"},
    {{7, "D"}, "B"},
    {{7, "E"}, "C"},
    {{7, "F"}, "D"},
    {{7, "G"}, "E"},
    {{7, "H"}, "F"},
    {{7, "I"}, "G"},
    {{7, "J"}, "H"},
    {{7, "K"}, "I"},
    {{7, "L"}, "J"},
    {{7, "M"}, "K"},
    {{7, "N"}, "L"},
    {{7, "O"}, "M"},
    {{7, "P"}, "N"},
    {{7, "Q"}, "O"},
    {{7, "R"}, "P"},
    {{7, "S"}, "Q"},
    {{7, "T"}, "R"},
    {{7, "U"}, "S"},
    {{7, "V"}, "T"},
    {{7, "W"}, "U"},
    {{7, "X"}, "V"},
    {{7, "Y"}, "W"},
    {{7, "Z"}, "X"},
    {{7, "a"}, "Y"},
    {{7, "b"}, "Z"},
    {{7, "c"}, "a"},
    {{7, "d"}, "b"},
    {{7, "e"}, "c"},
    {{7, "f"}, "d"},
    {{7, "g"}, "e"},
    {{7, "h"}, "f"},
    {{7, "i"}, "g"},
    {{7, "j"}, "h"},
    {{7, "k"}, "i"},
    {{7, "l"}, "j"},
    {{7, "m"}, "k"},
    {{7, "n"}, "l"},
    {{7, "o"}, "m"},
    {{7, "p"}, "n"},
    {{7, "q"}, "o"},
    {{7, "r"}, "p"},
    {{7, "s"}, "q"},
    {{7, "t"}, "r"},
    {{7, "u"}, "s"},
    {{7, "v"}, "t"},
    {{7, "w"}, "u"},
    {{7, "x"}, "v"},
    {{7, "y"}, "w"},
    {{7, "z"}, "x"},
    {{7, "0"}, "y"},
    {{7, "1"}, "z"},
    {{7, "2"}, "0"},
    {{7, "3"}, "1"},
    {{7, "4"}, "2"},
    {{7, "5"}, "3"},
    {{7, "6"}, "4"},
    {{7, "7"}, "5"},
    {{7, "8"}, "6"},
    {{7, "9"}, "7"},
    {{7, ";"}, "8"},
    {{7, ":"}, "9"},
    {{7, "/"}, ";"},
    {{7, "`"}, ":"},
    {{7, "~"}, "/"},
    {{7, "["}, "`"},
    {{7, "{"}, "~"},
    {{7, "("}, "["},
    {{7, ")"}, "{"},
    {{8, "}"}, "{"},
    {{8, "]"}, "("},
    {{8, "?"}, ")"},
    {{8, "%"}, "}"},
    {{8, "!"}, "]"},
    {{8, "A"}, "?"},
    {{8, "B"}, "%"},
    {{8, "C"}, "!"},
    {{8, "D"}, "A"},
    {{8, "E"}, "B"},
    {{8, "F"}, "C"},
    {{8, "G"}, "D"},
    {{8, "H"}, "E"},
    {{8, "I"}, "F"},
    {{8, "J"}, "G"},
    {{8, "K"}, "H"},
    {{8, "L"}, "I"},
    {{8, "M"}, "J"},
    {{8, "N"}, "K"},
    {{8, "O"}, "L"},
    {{8, "P"}, "M"},
    {{8, "Q"}, "N"},
    {{8, "R"}, "O"},
    {{8, "S"}, "P"},
    {{8, "T"}, "Q"},
    {{8, "U"}, "R"},
    {{8, "V"}, "S"},
    {{8, "W"}, "T"},
    {{8, "X"}, "U"},
    {{8, "Y"}, "V"},
    {{8, "Z"}, "W"},
    {{8, "a"}, "X"},
    {{8, "b"}, "Y"},
    {{8, "c"}, "Z"},
    {{8, "d"}, "a"},
    {{8, "e"}, "b"},
    {{8, "f"}, "c"},
    {{8, "g"}, "d"},
    {{8, "h"}, "e"},
    {{8, "i"}, "f"},
    {{8, "j"}, "g"},
    {{8, "k"}, "h"},
    {{8, "l"}, "i"},
    {{8, "m"}, "j"},
    {{8, "n"}, "k"},
    {{8, "o"}, "l"},
    {{8, "p"}, "m"},
    {{8, "q"}, "n"},
    {{8, "r"}, "o"},
    {{8, "s"}, "p"},
    {{8, "t"}, "q"},
    {{8, "u"}, "r"},
    {{8, "v"}, "s"},
    {{8, "w"}, "t"},
    {{8, "x"}, "u"},
    {{8, "y"}, "v"},
    {{8, "z"}, "w"},
    {{8, "0"}, "x"},
    {{8, "1"}, "y"},
    {{8, "2"}, "z"},
    {{8, "3"}, "0"},
    {{8, "4"}, "1"},
    {{8, "5"}, "2"},
    {{8, "6"}, "3"},
    {{8, "7"}, "4"},
    {{8, "8"}, "5"},
    {{8, "9"}, "6"},
    {{8, ";"}, "7"},
    {{8, ":"}, "8"},
    {{8, "/"}, "9"},
    {{8, "`"}, ";"},
    {{8, "~"}, ":"},
    {{8, "["}, "/"},
    {{8, "{"}, "`"},
    {{8, "("}, "~"},
    {{8, ")"}, "["},
    {{9, "}"}, "["},
    {{9, "]"}, "{"},
    {{9, "?"}, "("},
    {{9, "%"}, ")"},
    {{9, "!"}, "}"},
    {{9, "A"}, "}"},
    {{9, "B"}, "?"},
    {{9, "C"}, "%"},
    {{9, "D"}, "!"},
    {{9, "E"}, "A"},
    {{9, "F"}, "B"},
    {{9, "G"}, "C"},
    {{9, "H"}, "D"},
    {{9, "I"}, "E"},
    {{9, "J"}, "F"},
    {{9, "K"}, "G"},
    {{9, "L"}, "H"},
    {{9, "M"}, "I"},
    {{9, "N"}, "J"},
    {{9, "O"}, "K"},
    {{9, "P"}, "L"},
    {{9, "Q"}, "M"},
    {{9, "R"}, "N"},
    {{9, "S"}, "O"},
    {{9, "T"}, "P"},
    {{9, "U"}, "Q"},
    {{9, "V"}, "R"},
    {{9, "W"}, "S"},
    {{9, "X"}, "T"},
    {{9, "Y"}, "U"},
    {{9, "Z"}, "V"},
    {{9, "a"}, "W"},
    {{9, "b"}, "X"},
    {{9, "c"}, "Y"},
    {{9, "d"}, "Z"},
    {{9, "e"}, "a"},
    {{9, "f"}, "b"},
    {{9, "g"}, "c"},
    {{9, "h"}, "d"},
    {{9, "i"}, "e"},
    {{9, "j"}, "f"},
    {{9, "k"}, "g"},
    {{9, "l"}, "h"},
    {{9, "m"}, "i"},
    {{9, "n"}, "j"},
    {{9, "o"}, "k"},
    {{9, "p"}, "l"},
    {{9, "q"}, "m"},
    {{9, "r"}, "n"},
    {{9, "s"}, "o"},
    {{9, "t"}, "p"},
    {{9, "u"}, "q"},
    {{9, "v"}, "r"},
    {{9, "w"}, "s"},
    {{9, "x"}, "t"},
    {{9, "y"}, "u"},
    {{9, "z"}, "v"},
    {{9, "0"}, "w"},
    {{9, "1"}, "x"},
    {{9, "2"}, "y"},
    {{9, "3"}, "z"},
    {{9, "4"}, "0"},
    {{9, "5"}, "1"},
    {{9, "6"}, "2"},
    {{9, "7"}, "3"},
    {{9, "8"}, "4"},
    {{9, "9"}, "5"},
    {{9, ";"}, "6"},
    {{9, ":"}, "7"},
    {{9, "/"}, "8"},
    {{9, "`"}, "9"},
    {{9, "~"}, ";"},
    {{9, "["}, ":"},
    {{9, "{"}, "/"},
    {{9, "("}, "`"},
    {{9, ")"}, "~"},
    {{10, "}"}, "~"},
    {{10, "]"}, "["},
    {{10, "?"}, "{"},
    {{10, "%"}, "("},
    {{10, "!"}, ")"},
    {{10, "A"}, "}"},
    {{10, "B"}, "]"},
    {{10, "C"}, "?"},
    {{10, "D"}, "%"},
    {{10, "E"}, "!"},
    {{10, "F"}, "A"},
    {{10, "G"}, "B"},
    {{10, "H"}, "C"},
    {{10, "I"}, "D"},
    {{10, "J"}, "E"},
    {{10, "K"}, "F"},
    {{10, "L"}, "G"},
    {{10, "M"}, "H"},
    {{10, "N"}, "I"},
    {{10, "O"}, "J"},
    {{10, "P"}, "K"},
    {{10, "Q"}, "L"},
    {{10, "R"}, "M"},
    {{10, "S"}, "N"},
    {{10, "T"}, "O"},
    {{10, "U"}, "P"},
    {{10, "V"}, "Q"},
    {{10, "W"}, "R"},
    {{10, "X"}, "S"},
    {{10, "Y"}, "T"},
    {{10, "Z"}, "U"},
    {{10, "a"}, "V"},
    {{10, "b"}, "W"},
    {{10, "c"}, "X"},
    {{10, "d"}, "Y"},
    {{10, "e"}, "Z"},
    {{10, "f"}, "a"},
    {{10, "g"}, "b"},
    {{10, "h"}, "c"},
    {{10, "i"}, "d"},
    {{10, "j"}, "e"},
    {{10, "k"}, "f"},
    {{10, "l"}, "g"},
    {{10, "m"}, "h"},
    {{10, "n"}, "i"},
    {{10, "o"}, "j"},
    {{10, "p"}, "k"},
    {{10, "q"}, "l"},
    {{10, "r"}, "m"},
    {{10, "s"}, "n"},
    {{10, "t"}, "o"},
    {{10, "u"}, "p"},
    {{10, "v"}, "q"},
    {{10, "w"}, "r"},
    {{10, "x"}, "s"},
    {{10, "y"}, "t"},
    {{10, "z"}, "u"},
    {{10, "0"}, "v"},
    {{10, "1"}, "w"},
    {{10, "2"}, "x"},
    {{10, "3"}, "y"},
    {{10, "4"}, "z"},
    {{10, "5"}, "0"},
    {{10, "6"}, "1"},
    {{10, "7"}, "2"},
    {{10, "8"}, "3"},
    {{10, "9"}, "4"},
    {{10, ";"}, "5"},
    {{10, ":"}, "6"},
    {{10, "/"}, "7"},
    {{10, "`"}, "8"},
    {{10, "~"}, "9"},
    {{10, "["}, ";"},
    {{10, "{"}, ":"},
    {{10, "("}, "/"},
    {{10, ")"}, "`"},
};





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

void logdebug(std::string data2, bool complete) {
    data2 = "[DEBUG] - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void loginfo(std::string data2, bool complete) {
    data2 = "[INFO] - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logwarning(std::string data2, bool complete) {
    data2 = "[WARNING] - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logcritical(std::string data2, bool complete) {
    data2 = "[CRITICAL] - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logerror(std::string headerdata2, std::string errormessage) {
    std::string data2 = "[ERROR] - " + headerdata2 + " - " + errormessage;
    sendtolog(data2);
}

void debugout(std::string data2) {
    logdebug(data2, true);
}




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




/////////////////////////
// THE MAIN CRASH LOOP //
/////////////////////////
// HARDCRASH - PERMANENT LOCKOUT
// SECTOR - SECTOR THAT IS AFFECTED (0-P80; 1-P443; 2-P11829; 3-P11830; 4-MARIADB; 5-MARIADBHANDLER; 6-STATUSMARIADB; 7-READ/WRITEERROR; 8-ENCRYPTION_ERROR; 9-COG_STORE_ERROR; 10-ERROR_MODULE)
// SEVERITY - SEVERITY OF INCIDENT
// MODULE - NAME OF MODULE TO BE DISPLAYED
// HEADERMESSAGE - MESSAGE TO BE DISPLAYED IN RUNNING LOG FILE!
// ERRORMESSAGE - LIBRARY MESSAGE (IF APPLICABLE :) )
int crashloop(int sector, int severity, bool loopback, std::string module, std::string headermessage, std::string errormessage) {
    std::string hardcrash = servercrash[std::pair{sector,severity}];
    if (errormessage == "") {
        errormessage = "No further information provided...";
    }

    // FIX THIS WITH NEW PARAMETERS
    if (hardcrash == "true") {
        // HARD CRASH
        // ADD MORE HERE LATER FOR FULL CRASH TO QUICK AND WRITE TO FILES!
        logerror("ERROR MODULE", "HARD CRASH CALLED BUT NOT IMPLEMENTED!");

    } else {
        // SOFT CRASH


        // ADD MARIADB ERROR COUNTER!!!
        std::ofstream errormodule;
        errormodule.open(errorlog);
        if (errormodule.is_open()) {
            errormodule << "[ERROR] - " << module << " - " << headermessage << " - " << errormessage << std::endl;
        } else {
            if (loopback == true) {
                logerror("ERROR MODULE", "UNABLE TO WRITE TO ERROR LOG (ERROR 2)");
                crashloop(sector, 3, true, module, headermessage, errormessage);
            } else {
                int res26 = system(createnewerrorlogfile);
                if (res26 != 0) {
                    logerror(module, headermessage + errormessage);
                    logerror("ERROR MODULE", "UNABLE TO CREATE ERROR LOG (ERROR 1)");
                    crashloop(sector, 3, true, module, headermessage, errormessage);
                } else {
                    logerror(module, headermessage + errormessage);
                    crashloop(sector, severity, true, module, headermessage, errormessage);
                }
            }
        }
    }
    return 1;
}




////////////////////////////
////////////////////////////
//// MARIADB OPERATIONS ////
////////////////////////////
////////////////////////////

// MARIADB PING
int mariadb_ping() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    loginfo("MARIADB - Checking MariaDB Status...", false);
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));

        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());

        // Execute query
        sql::ResultSet *res = stmnt->executeQuery("SELECT user FROM credentials");
        
        if (res->next() == true) {
            sendtolog("OK");
            return 0;
        } else {
            sendtolog("ERROR");
            return 1;
        }
        //std::cout << "User = " << res->getString(1);
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        sendtolog("ERROR");
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// ADD IP ADDRESS IN serversecurity
int mariadb_ADDIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        int timetoreset = time(NULL) + 120;
        
        // Execute query
        std::string executequery34 = mariadbaddaddrheader + ipaddr + "'," + "1," + "false," + std::to_string(timetoreset) + ")";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);
        
        return 0;
    }

    // ADD SQL EXCEPTION
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    } 
    return 255;
}

// CHECK FOR IP ADDRESS IN serversecurity
int mariadb_CHECKIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));

        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery21 = mariadbcheckaddrheader + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery21);
        
        if (res->next() == true) {
            // FIX THIS PROBLEM, NOT READING RESULT OF A CLOSED SET"?"
            return 1;
        } else {
            mariadb_ADDIPADDR(ipaddr);
            return 0;
        }
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    } 

    // RETURN 255 - IPADDR NOT FOUND IN DB PREVIOUSLY
    return 255;
}

// ADD BLOCKED IP ADDRESS IN serversecurity
int mariadb_BLOCKIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbblockipaddrheader + ipaddr + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery36);
        
        return 0;
    }
    
    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// UNBLOCK IP ADDRESS IN serversecurity
int mariadb_UNBLOCKIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbubblockipaddrheader + ipaddr + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery36);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// ADD PACKET TO IP ADDRESS IN serversecurity
int mariadb_ADDPACKETTOIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbreadpacketcountipaddr + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        if (res->next() == true) {
            int testers = res->getInt(1);
            testers = testers + 1;

            // Instantiate Driver
            sql::Driver* driver = sql::mariadb::get_driver_instance();

            // Configure Connection
            sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
            sql::Properties properties({{"user", "root"}, {"password", legendstring}});

            // Establish Connection
            std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


            // Create a new Statement
            std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
            
            // Execute query
            std::string executequery36 = mariadbwritepacketcountipaddr + std::to_string(testers) + mariadbwritepacketcountipaddr2 + ipaddr + "'";
            sql::ResultSet *res = stmnt->executeQuery(executequery36);
            
            return 0;
        } else {
            return 1;
        }
        return 1;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// REMOVE PACKET FROM IP ADDRESS
int mariadb_REMOVEPACKETFROMIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbreadpacketcountipaddr + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        if (res->next() == true) {
            int testers = res->getInt(1);
            testers = testers - 1;

            // Instantiate Driver
            sql::Driver* driver = sql::mariadb::get_driver_instance();

            // Configure Connection
            sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
            sql::Properties properties({{"user", "root"}, {"password", legendstring}});

            // Establish Connection
            std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


            // Create a new Statement
            std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
            
            // Execute query
            std::string executequery36 = mariadbwritepacketcountipaddr + std::to_string(testers) + mariadbwritepacketcountipaddr2 + ipaddr + "'";
            sql::ResultSet *res = stmnt->executeQuery(executequery36);
            
            return 0;
        } else {
            return 1;
        }
        return 1;
    }
    
    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// IP ADDRESS IS DEVELOPER BLOCKED AND WON'T CONTINUE SEARCHING
bool mariadb_READDEVBLOCK(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbDEVBLOCKFLAG + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        if (res->next() == true) {
            if (res->getInt(1) == true) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
        return false;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return true;
    }   
    return true;
}

// REMOVE OLD IP ADDR
int mariadb_REMOVEOLDIPADDR(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbremoveoldipaddr + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// CLEAR IP ADDRESSES (MAINTENANCE AND DECREASE PACKETS FOR OTHER IPs)
int mariadb_MAINTENANCE() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbmaintenance;
        sql::ResultSet *res = stmnt->executeQuery(executequery36);
        std::string ipaddr;
        std::istream *blob = res -> getBlob(1);
        while(blob->eof() != true) {
            *blob >> ipaddr;
            bool devflagset = mariadb_READDEVBLOCK(ipaddr);
            if (devflagset != true) {
                int resultofcheck = mariadb_CHECKIPADDR(ipaddr);
                if (resultofcheck == 1) {
                    // DO NOTHING - ADD MORE FOR TEMP BANS BUT NOT RIGHT NOW
                    int test = 0;
                } else {
                    // REMOVE OLD IP ADDRESSES THAT DON'T CORRESPOND TO ANYTHING IMPORTANT
                    int remove = mariadb_REMOVEOLDIPADDR(ipaddr);
                }
            }
        }
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 255;
}

// MARIADB LAST TIME TO PACKET
int mariadb_LASTTIMETOPACKET(std::string ipaddr) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbpacketheader + ipaddr + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        int lasttime = res->getInt(1);
        return lasttime;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 0;
    }   
    return 0;
}

// READ THE VALUE OF PI API
std::string mariadbREAD_VALUEPIAPI(std::string user) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbuserpiapikey + user + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        std::istream *hello = res->getBlob(1);
        std::string piapi = "";
        *hello >> piapi;
        return piapi;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return "ERROR";
    }   
    return "ERROR";
}

// READ THE VALU7E OF ROUTER API
std::string mariadbREAD_VALUEROUTERAPI(std::string user, int apinumber) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        std::string executequery38 = "";
        
        // SWITCH TO MAKE RIGHT NUMBER
        switch(apinumber) {
            case 0:
                executequery38 = "SELECT honeyrouterapi FROM credentials WHERE user = '";
                break;
            case 1:
                executequery38 = "SELECT honeyrouterapi2 FROM credentials WHERE user = '";
                break;
            case 2:
                executequery38 = "SELECT honeyrouterapi3 FROM credentials WHERE user = '";
                break;
            case 3:
                executequery38 = "SELECT honeyrouterapi4 FROM credentials WHERE user = '";
                break;
            case 4:
                executequery38 = "SELECT honeyrouterapi5 FROM credentials WHERE user = '";
                break;
        }

        // Execute query
        executequery38 = executequery38 + user + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery38);
        std::istream *hello = res->getBlob(1);
        std::string rouapi = "";
        *hello >> rouapi;
        return rouapi;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return "ERROR";
    }   
    return "ERROR";
}

// READ THE VALUE OF THE EMAIL ADDRESS
std::string mariadbREAD_EMAILADDRESS(std::string user) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbreademail + user + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        std::istream *hello = res->getBlob(1);
        std::string piapi = "";
        *hello >> piapi;
        return piapi;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return "ERROR";
    }   
    return "ERROR";
}

// RESET THE PASSWORD DB ACCESS
int mariadbRESET_PASSWORD(std::string user, std::string pass, std::string pass2) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        if (pass == pass2) {
            // Instantiate Driver
            sql::Driver* driver = sql::mariadb::get_driver_instance();

            // Configure Connection
            sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
            sql::Properties properties({{"user", "root"}, {"password", legendstring}});

            // Establish Connection
            std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


            // Create a new Statement
            std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
            
            // Execute query
            std::string executequery36 = mariadbresetpasswordheader + pass + "' WHERE user = '" + user + "'";
            sql::ResultSet *res = stmnt->executeQuery(executequery36);

            return 0;
        }
        return 2;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// RESET THE EMAIL DB ACCESS
/*
int mariadbRESET_EMAIL(std::string user, std::string emailaddress) {


    return 0;
}
*/

// MARIADB PI API KEY VALIDATION
bool mariadbPIAPI_keyvalid(std::string apikey) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery21 = headerforAPIKeyValid + "'" + apikey + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery21);
        
        if (res->next() == true) {
            loginfo("TRUE", true);
            // FIX THIS PROBLEM, NOT READING RESULT OF A CLOSED SET"?"
            return true;
        } else {
            return false;
        }
        return false;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return false;
    }   
    return false;
}

// MARIADB ROUTER API KEY VALIDATION
// FIX LATER
bool mariadbROUTERAPI_keyvalid(std::string apikey) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        





        // FIX THIS LOOP BY ANALYZING ONE_BY_ONE AND COMBINING AT END OF RESULT WITH 5 ELSES    




        std::string executequery22 = headerforAPIKeyValid3 + "'" + apikey + "'";
        std::string executequery23 = headerforAPIKeyValid4 + "'" + apikey + "'";
        std::string executequery24 = headerforAPIKeyValid5 + "'" + apikey + "'";
        std::string executequery25 = headerforAPIKeyValid6 + "'" + apikey + "'";
        std::string executequery26 = headerforAPIKeyValid2 + "'" + apikey + "'";
        sql::ResultSet *res2 = stmnt->executeQuery(executequery22);
        sql::ResultSet *res3 = stmnt->executeQuery(executequery23);
        sql::ResultSet *res4 = stmnt->executeQuery(executequery24);
        sql::ResultSet *res5 = stmnt->executeQuery(executequery25);
        sql::ResultSet *res6 = stmnt->executeQuery(executequery26);


        if (res2->next() == true || res3->next() == true ||res4->next() == true ||res5->next() == true ||res6->next() == true) {
            logcritical("MATCH SEEN", true);
            return true;
        } else {
            return false;
        }
        return false;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return false;
    }   
    return false;
}

// MARIADB NEW USER/PASSWORD/EMAIL INSERTION
// FIX THIS
int mariadbNEW_USER(std::string username, std::string password, std::string pass2, std::string emailaddress, std::string country, std::string referrer, std::string securitykey) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery32 = insertintocredheader + valuestoinsertupe + valuesheader + "'" + username + "'" + commaheader + "'" + password + "'" + commaheader + "'" + emailaddress + "'" + commaheader + " true" + ")";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery32);


        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB INSERT NEW HONEY PI API KEY
int mariadbINSERT_PIKEY(std::string honeypikey, std::string username) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery34 = updatecredheader + valuetoinsertSETPIAPI + "'" + honeypikey + "'" + valuetoinsertWHERE + "'" + username + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB INSERT NEW HONEY ROUTER API 
// FIX THIS PROBLEM OF NEEDING 5 APIS FOR ONE ACCOUNT
int mariadbINSERT_ROUTERKEY(std::string routerkey, int slottoinsert, std::string username) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        if (slottoinsert == 0) {
            // FIX TO ADD READ AND DETERMINE THE FIRST EMPTY SLOT
        }
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery34 = updatecredheader + valuetoinsertSETPIAPI + "'" + routerkey + "'" + valuetoinsertWHERE + "'" + username + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB VALIDATE USER CREDENTIALS
bool mariadbVALIDATE_USER(std::string username, std::string password) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        bool credentialsmatch = false;
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbverifyuserpassheader + username + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);
        if (res->next() == true) {
            std::istream *hello = res->getBlob(1);
            std::string piapi = "";
            *hello >> piapi;

            if (piapi == password) {
                credentialsmatch = true;
                // Instantiate Driver
                sql::Driver* driver = sql::mariadb::get_driver_instance();

                // Configure Connection
                sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
                sql::Properties properties({{"user", "root"}, {"password", legendstring}});

                // Establish Connection
                std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


                // Create a new Statement
                std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
                
                // Execute query
                std::string executequery362 = mariadbuserverifyvalidheader + username + "'";
                sql::ResultSet *res2 = stmnt->executeQuery(executequery362);

                if (res2->next() == true) {
                    std::istream *hello3 = res2->getBlob(1);
                    std::string piapi1 = "";
                    *hello3 >> piapi1;
                    if (piapi1 == "1") {
                        loginfo("THAT IS TRUE", true);
                        return true;
                    } else {
                        return false;
                    }
                }
            } else {
                credentialsmatch = false;
                return false;
            }
        } else {

            // ADD INVALID USER
            return false;
        }    

        // ADD INVALID USER
        return false;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return false;;
    }   
    return false;
}

// MARIADB INSERT NEW CLIENT SESSION KEY
int mariadbINSERT_SESSIONKEY(std::string username, std::string sessionToken) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery34 = mariadbinsertsessionheader + sessionToken + "' WHERE user='" + username + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB CHECK-IN SCRIPT - CHECKIN FOR HONEYPOTS
int mariadbCHECKIN_HONEYPI(std::string apikey) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery34 = mariadbcheckinhoneypiheader + apikey + "'";
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB ROTATE CREDENTIALS/HOUR
int mariadbROTATE_CREDENTIALShour() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// REMOVE ALL SESSION TOKENS EVERY 24 HOURS
int mariadbREMOVE_SESSIONTOKENS() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery34 = mariadbloadalluserswithsessiontokens;
        sql::ResultSet *res6 = stmnt->executeQuery(executequery34);
        std::string user;
        std::istream *blob = res6 -> getBlob(1);
        while(blob->eof() != true) {
            *blob >> user;
            // Instantiate Driver
            sql::Driver* driver = sql::mariadb::get_driver_instance();

            // Configure Connection
            sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
            sql::Properties properties({{"user", "root"}, {"password", legendstring}});

            // Establish Connection
            std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


            // Create a new Statement
            std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
            
            // Execute query
            std::string executequery36 = mariadbremovesessionID24hours;
            sql::ResultSet *res8 = stmnt->executeQuery(executequery36);
        }
        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB ROTATE CREDENTIALS/DAY
int mariadbROTATE_CREDENTIALSday() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB INVALIDATE CREDENTIALS
int mariadbINVALIDATE_CREDENTIALS(std::string user, std::string pass, std::string email) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB PAYMENT RECEIVED
int mariadbRECEIVE_PAYMENT(std::string user, bool truereceive) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB SET PAYMENT PLAN
int mariadbSET_PAYMENT(std::string user, int paymentlevel) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// REMOVE PI API FROM DB
int mariadbREMOVE_PIAPI(std::string user) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        // Instantiate Driver
        sql::Driver* driver = sql::mariadb::get_driver_instance();

        // Configure Connection
        sql::SQLString url("jdbc:mariadb://172.17.0.2:3306/honey");
        sql::Properties properties({{"user", "root"}, {"password", legendstring}});

        // Establish Connection
        std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));


        // Create a new Statement
        std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
        
        // Execute query
        std::string executequery36 = mariadbremovepiapiheader + user + "'";
        sql::ResultSet *res = stmnt->executeQuery(executequery36);

        return 0;
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// REMOVE ROUTER API FROM DB
int mariadbREMOVE_ROUTERAPI(std::string user, int number) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// REMOVE USER FROM DB
int mariadbREMOVE_USER(std::string user, std::string pass) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// CHANGE RUNNING PORT STATUS IN SERVER DB
// 0 - 80; 1 - 443; 2 - 11829; 3 - 11830
int mariadbCHANGEPORTSTATUS(int port,bool status) {
    std::string dbpayload = "";
//    dbpayload = mariadbchangeportstatusheader[{port, status}];
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// REVIEW SERVER STATUS
int mariadbREVIEWSTATUS() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// ADD COG TO DB
int mariadbADDCOGTODB(std::string) {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// RETURN TOP MOST COG
std::string mariadbTOPCOG() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return "";
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return "ERROR";
    }   
    return "ERROR";
}

// CLEAR COGS
int mariadbCLEARCOGS_START() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// MARIADB CLEAR COGS
int mariadbCLEARCOGS_READ() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}

// SET FLAG TO PREVENT COGS FROM BEING ADDED WHILE THEY ARE BEING WRITTEN
int mariadbSETCOGLOCKINDB() {
    // ADD TRY FUNCTION FOR EXCEPTION HANDLING
    try {
        return 0;
    }

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        crashloop(5, 1, false, "MARIADB-HANDLER", "ERROR IN TASK: ", e.what());
        std::cerr << "Error in task: " << e.what() << std::endl;
        return 1;
    }   
    return 1;
}





/////////////////////////////////////
//// GENERATE API RANDOM STRINGS ////
/////////////////////////////////////
std::string generateRandomStringHoneyPI() {
    loginfo("CREATING NEW HoneyPi API KEY", true);

    // Define the list of possible characters
    const std::string CHARACTERS = charactermap;

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
    loginfo("CREATING NEW ROUTER API KEY", true);

    // Define the list of possible characters
    const std::string CHARACTERS = charactermap;

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
    loginfo("CREATING NEW RANDOM FILENAME", true);

    timedetector();

    // Define the list of possible characters
    const std::string CHARACTERS = charactermap;

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

std::string generateRandomClientKey() {
    // Define the list of possible characters
    const std::string CHARACTERS = charactermap;

    // Create a random number generator
    std::random_device rd;
    std::mt19937 generator(rd());

    // Create a distribution to uniformly select from all
    // characters
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    // Generate the random string
    std::string random_string = "SS";
    for (int i = 0; i < 62; ++i) {
        random_string += CHARACTERS[distribution(generator)];
    }

    return random_string;
}





////////////////////////////////
////////////////////////////////
//// CURL/UPDATE OPERATIONS ////
////////////////////////////////
////////////////////////////////
// WRITE CALLBACK FOR SERVER DEVICE CHECK
size_t write_callbackserver(char *ptr, size_t size, size_t nmemb, void *userdata) {
    updatefileinformationserver = updatefileinformationserver + ptr;
    return updatefileinformationserver.length();
}

// WRITE CALLBACK FOR CLIENT DEVICE CHECK
size_t write_callbackhoneypi(char *ptr, size_t size, size_t nmemb, void *userdata) {
    updatefileinformationhoneypi = updatefileinformationhoneypi + ptr;
    return updatefileinformationhoneypi.length();
}

// CURL FOR SERVER DEVICE CHECK
void checkforserverupdates() {
    CURL *curl = curl_easy_init();
    char errcurlno[CURL_ERROR_SIZE];
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errcurlno);
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/server.txt");
        res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callbackserver);

        // PERFORM CURL
        res = curl_easy_perform(curl);
        //std::cout << "RECEIVED GITHUB INFORMATION: " << updatefileinformationserver << std::endl;

        if (updatefileinformationserver == "") {
            logcritical("RECEIVED NULL INSTANCE FOR SERVER VERSION! - ", false);
            sendtologopen(errcurlno);
            sendtologopen(" - ");
            sendtolog(curl_easy_strerror(res));
        }
    
        // CLEAN UP CURL COMMAND
        curl_easy_cleanup(curl);
    } else {
        logcritical("AN ERROR OCCURRED IN CURL - ", false);
        sendtologopen(errcurlno);
        sendtologopen(" - ");
        sendtolog(curl_easy_strerror(res));
    }
}

// CURL FOR CLIENT DEVICE CHECK
void checkforhoneypiupdates() {
    CURL *curl = curl_easy_init();
    char errcurlno[CURL_ERROR_SIZE];
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errcurlno);
    if(curl) {
        res = curl_easy_setopt(curl, CURLOPT_URL, "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/mainversion.txt");
        res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callbackhoneypi);

        // PERFORM CURL
        res = curl_easy_perform(curl);
        //std::cout << "RECEIVED GITHUB INFORMATION: " << updatefileinformationhoneypi << std::endl;

        if (updatefileinformationhoneypi == "") {
            logcritical("RECEIVED NULL INSTANCE FOR CLIENT VERSION! - ", false);
            sendtologopen(errcurlno);
            sendtologopen(" - ");
            sendtolog(curl_easy_strerror(res));
        }
    
        // CLEAN UP CURL COMMAND
        curl_easy_cleanup(curl);
    } else {
        logcritical("AN ERROR OCCURRED IN CURL - ", false);
        sendtologopen(errcurlno);
        sendtologopen(" - ");
        sendtolog(curl_easy_strerror(res));
    }
}

// CHECK TO SEE IF LATEST HONEYPI VERSION FOR CLIENT DEVICES HAS CHANGED
bool checkhoneypiupdateavailable() {
    checkforhoneypiupdates();
    std::string aStd = updatefileinformationhoneypi;
    if (aStd.length() >= 60) {
        std::string header1 = aStd.substr(0, 14);
        if (header1 == "latest.main = ") {
            std::string version1 = aStd.substr(14,5);
            std::string nextcharacter = aStd.substr(19,2);
            latesthoneyPIMmainversion = version1.substr(0,1);
            latesthoneyPIMminorversion = version1.substr(2,1);
            latesthoneyPIMhotfixversion = version1.substr(4,1);
            std::string nextversionheader = aStd.substr(20, 14);
            if (nextversionheader == "latest.beta = ") {
                std::string version2 = aStd.substr(34,5);
                std::string nextcharacter = aStd.substr(40,2);
                latesthoneyPIBmainversion = version2.substr(0,1);
                latesthoneyPIBminorversion = version2.substr(2,1);
                latesthoneyPIBhotfixversion = version2.substr(4,1);
                std::string nextversionheader2 = aStd.substr(40, 14);
                if (nextversionheader2 == "latest.test = ") {
                    std::string version4 = aStd.substr(54,5);
                    latesthoneyPITmainversion = version4.substr(0,1);
                    latesthoneyPITminorversion = version4.substr(2,1);
                    latesthoneyPIThotfixversion = version4.substr(4,1);
                    sendtolog("Done");
                    return true;
                } else {
                    sendtolog("ERROR");
                    logwarning("INVALID CLIENT_VERSION RECEIVED-3!", true);
                    loginfo(aStd, true);
                    std::cout << aStd.length() << std::endl;
                    return false;
                }
            } else {
                sendtolog("ERROR");
                logwarning("INVALID CLIENT_VERSION RECEIVED-2!", true);
                loginfo(aStd, true);
                std::cout << aStd.length() << std::endl;
                return false;
            }
        } else {
            sendtolog("ERROR");
            logwarning("INVALID CLIENT_VERSION RECEIVED-1!", true);
            loginfo(aStd, true);
            std::cout << aStd.length() << std::endl;
            return false;
        }
    } else {
        sendtolog("ERROR");
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
    if (honeymainversion != latesthoneymainMversion || honeyminorversion != latesthoneyminorMversion || honeyhotfixversion != latesthoneyhotfixMversion) {
        sendtolog("New Server Update Available!");
        return true;
    } else {
        sendtolog("No New Version Found");
        return false;
    }
}

// CHECK THAT SERVER HAS A VALID HEADER
bool checkserverupdateavailable() {
    checkforserverupdates();
    std::string aStd = updatefileinformationserver;
    if (aStd.length() >=19) {
        std::string header1 = aStd.substr(0, 14);
        if (header1 == "latest.main = ") {
            std::string version1 = aStd.substr(14,5);
            latesthoneymainMversion = version1.substr(0,1);
            latesthoneyminorMversion = version1.substr(2,1);
            latesthoneyhotfixMversion = version1.substr(4,1);
            bool updateavailable23 = serverupdateavailable();
            return updateavailable23;
        } else {
            sendtolog("ERROR");
            logcritical("INVALID UPDATE HEADER RECEIVED!", true);
            return false;
        }
    } else {
        sendtolog("ERROR");
        logwarning("UNABLE TO CHECK FOR UPDATES!", true);
        return false;
    }
    return false;
}

// UPDATE SCRIPT - UPDATE TO NEW SERVER VERSION
int updatetoNewServer() {
    // START PROCESS OF UPDATING
    logwarning("SERVER STARTING TO UPDATE!", true);

    // SMALL DELAY
    sleep(2);

    // SERVER CHECK DOCKER STATUS
    loginfo("Checking for Docker Control...", false);
    int res97 = system(dockerpscommand);
    if (res97 != 0) {
        sendtolog("ERROR!");
        logcritical("UNABLE TO COMPLETE DOCKER COMMAND!", true);
        logcritical("TERMINATING UPDATE!", true);
        return 1;
    } else {
        sendtolog("done");
    }

    // CLEAR COG FOLDER
    loginfo("Emptying COGs in DB...", false);
    int res98 = mariadbCLEARCOGS_READ();
    if (res98 != 0) {
        sendtolog("ERROR!");
        logcritical("UNABLE TO COMPLETE MARIADB COGs!", true);
        logcritical("TERMINIATING UPDATE!", true);
    } else {
        sendtolog("done");
    }



    // CONTINUE SERVER UPDATES PROCESS HERE!


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
        sendtolog("");
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
                    sendtolog("ERROR");
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
        sendtolog("ERROR");
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
                    sendtolog("ERROR");
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
        sendtolog("ERROR");
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
                    sendtolog("ERROR");
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
                    sendtolog("ERROR");
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




////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// HACKSWEEP ENCRYPTION ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
// UNENCRYPT STRING
std::string ucryptHackSweep(std::string encryptedstring, std::string ekey) {

}

// ENCRYPT STRING
std::string encryotHackSweep(std::string ucryptstring) {
    
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
            logcritical("COG COULD NOT BE OPENED AT: ", false);
            sendtolog(coglocation);
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




//////////////////////////////////////////////
//////////////////////////////////////////////
//// MAIN ENCRYPTION / UNECNRYPTION LOOPS ////
//////////////////////////////////////////////
//////////////////////////////////////////////
int readipliststandard() {
    std::ifstream iplist231;
    iplist231.open(ipliststandardfile);
    // FIRST READ FILE TO UNECNRYPTED STRING
    if (iplist231.is_open() == true) {
        bool completiong = false;
        std::string templine;
        int timery9 = 0;
        int timer9max = 0;
        while (completiong == false) {
            getline(iplist231, templine);
            if (templine != "") {
                timery9 = timery9 + 1;
                if (timery9 >= timer9max) {
                    if (ipliststandardunencrypt != "") {
                        return 0;
                    } else {
                        return 2;
                    }
                }
            } else {
                ipliststandardunencrypt = ipliststandardunencrypt + templine + "\n";
            }
        }
        return 1;
    }
    return 1;
}

int encryptipliststandard() {
    int yargh = readipliststandard();
    if (yargh == 0) {
        std::string templine = ipliststandardunencrypt;
        int maxlength = ipliststandardunencrypt.length();
        if (maxlength > 1) {
            int current = 0;
            int crypt = int (rand() % 11);
            std::string currentcharacter;
            std::string newcharacter;
            bool matched = false;
            while (current < maxlength) {
                matched = false;
                currentcharacter = templine.substr(current, current + 1);
                current = current + 1;

                // TRY TO MATCH TO OPTION BELOW, OTHERWISE KEEP CHARACTER SAME!
                if (currentcharacter == "0") {
                    newcharacter = ecryptip[std::pair{crypt,0}];
                    matched = true;
                }
                if (currentcharacter == "1") {
                    newcharacter = ecryptip[std::pair{crypt,1}];
                    matched = true;
                }
                if (currentcharacter == "2") {
                    newcharacter = ecryptip[std::pair{crypt,2}];
                    matched = true;
                }
                if (currentcharacter == "3") {
                    newcharacter = ecryptip[std::pair{crypt,3}];
                    matched = true;
                }
                if (currentcharacter == "4") {
                    newcharacter = ecryptip[std::pair{crypt,4}];
                    matched = true;
                }
                if (currentcharacter == "5") {
                    newcharacter = ecryptip[std::pair{crypt,5}];
                    matched = true;
                }
                if (currentcharacter == "6") {
                    newcharacter = ecryptip[std::pair{crypt,6}];
                    matched = true;
                }
                if (currentcharacter == "7") {
                    newcharacter = ecryptip[std::pair{crypt,7}];
                    matched = true;
                }
                if (currentcharacter == "8") {
                    newcharacter = ecryptip[std::pair{crypt,8}];
                    matched = true;
                }
                if (currentcharacter == "9") {
                    newcharacter = ecryptip[std::pair{crypt,9}];
                    matched = true;
                }
                if (currentcharacter == ".") {
                    newcharacter = ecryptip[std::pair{crypt,10}];
                    matched = true;
                }
                if (currentcharacter == ":") {
                    newcharacter = ecryptip[std::pair{crypt,11}];
                    matched = true;
                }
                if (currentcharacter == ";") {
                    newcharacter = ecryptip[std::pair{crypt,12}];
                    matched = true;
                }
                if (currentcharacter == "n") {
                    newcharacter = ecryptip[std::pair{crypt,13}];
                    matched = true;
                }

                if (matched == false) {
                    newcharacter = currentcharacter;
                }
                ipliststandardENC = ipliststandardENC + newcharacter;
            }
            return 0;
        } else {
            return 2;
        }
    } else {
        return 1;
    }
    return 1;
}

int readipliststrict() {
    std::ifstream iplist231;
    iplist231.open(ipliststrictfile);
    // FIRST READ FILE TO UNECNRYPTED STRING
    if (iplist231.is_open() == true) {
        bool completiong = false;
        std::string templine;
        int timery9 = 0;
        int timer9max = 0;
        while (completiong == false) {
            getline(iplist231, templine);
            if (templine != "") {
                timery9 = timery9 + 1;
                if (timery9 >= timer9max) {
                    if (iplistSTRICTunencrypt != "") {
                        return 0;
                    } else {
                        return 2;
                    }
                }
            } else {
                iplistSTRICTunencrypt = iplistSTRICTunencrypt + templine + "\n";
            }
        }
        return 1;
    }
    return 1;
}

int encryptipliststrict() {
    int yargh = readipliststrict();
    if (yargh == 0) {
        std::string templine = iplistSTRICTunencrypt;
        int maxlength = iplistSTRICTunencrypt.length();
        if (maxlength > 1) {
            int current = 0;
            int crypt = int (rand() % 11);
            std::string currentcharacter;
            std::string newcharacter;
            bool matched = false;
            while (current < maxlength) {
                matched = false;
                currentcharacter = templine.substr(current, current + 1);
                current = current + 1;

                // TRY TO MATCH TO OPTION BELOW, OTHERWISE KEEP CHARACTER SAME!
                if (currentcharacter == "0") {
                    newcharacter = ecryptip[std::pair{crypt,0}];
                    matched = true;
                }
                if (currentcharacter == "1") {
                    newcharacter = ecryptip[std::pair{crypt,1}];
                    matched = true;
                }
                if (currentcharacter == "2") {
                    newcharacter = ecryptip[std::pair{crypt,2}];
                    matched = true;
                }
                if (currentcharacter == "3") {
                    newcharacter = ecryptip[std::pair{crypt,3}];
                    matched = true;
                }
                if (currentcharacter == "4") {
                    newcharacter = ecryptip[std::pair{crypt,4}];
                    matched = true;
                }
                if (currentcharacter == "5") {
                    newcharacter = ecryptip[std::pair{crypt,5}];
                    matched = true;
                }
                if (currentcharacter == "6") {
                    newcharacter = ecryptip[std::pair{crypt,6}];
                    matched = true;
                }
                if (currentcharacter == "7") {
                    newcharacter = ecryptip[std::pair{crypt,7}];
                    matched = true;
                }
                if (currentcharacter == "8") {
                    newcharacter = ecryptip[std::pair{crypt,8}];
                    matched = true;
                }
                if (currentcharacter == "9") {
                    newcharacter = ecryptip[std::pair{crypt,9}];
                    matched = true;
                }
                if (currentcharacter == ".") {
                    newcharacter = ecryptip[std::pair{crypt,10}];
                    matched = true;
                }
                if (currentcharacter == ":") {
                    newcharacter = ecryptip[std::pair{crypt,11}];
                    matched = true;
                }
                if (currentcharacter == ";") {
                    newcharacter = ecryptip[std::pair{crypt,12}];
                    matched = true;
                }
                if (currentcharacter == "n") {
                    newcharacter = ecryptip[std::pair{crypt,13}];
                    matched = true;
                }

                if (matched == false) {
                    newcharacter = currentcharacter;
                }
                iplistSTRICTENC = iplistSTRICTENC + newcharacter;
            }
            return 0;
        } else {
            return 2;
        }
    } else {
        return 1;
    }
    return 1;
}

int unencryptCOG() {




    return 0;
}



////////////////////////////
//// LOAD HTML INTO RAM ////
//////////////////////////// 

// PERMANENT LOAD INTO RAM!
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
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                mainhtmlpayload = mainhtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = mainhtmlpayload.length();
        mainhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + mainhtmlpayload;
        htmlmain.close();
        sendtolog("Done");
        return 0;
    } else {
        mainhtmlpayload = httpservererror;
        htmlmain.close();
        sendtolog("ERROR");
        return 1;
    }
    mainhtmlpayload = httpservererror;
    htmlmain.close();
    sendtolog("ERROR");
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
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                pricinghtmlpayload = pricinghtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = pricinghtmlpayload.length();
        pricinghtmlpayload = httpsuccess + std::to_string(length) + beforepayload + pricinghtmlpayload;
        htmlprice.close();
        sendtolog("Done");
        return 0;
    } else {
        pricinghtmlpayload = httpservererror;
        htmlprice.close();
        sendtolog("ERROR");
        return 1;
    }
    pricinghtmlpayload = httpservererror;
    htmlprice.close();
    sendtolog("ERROR");
    return 1;
}

int loadblogHTMLintoram() {
    std::string templine;
    std::ifstream bloghtml;
    blogpayload = "";
    bloghtml.open(bloghtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (bloghtml.is_open() == true) {
        while (completionht != true) {
            getline(bloghtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                blogpayload = blogpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = blogpayload.length();
        blogpayload = httpsuccess + std::to_string(length) + beforepayload + blogpayload;
        bloghtml.close();
        sendtolog("Done");
        return 0;
    } else {
        blogpayload = httpservererror;
        bloghtml.close();
        sendtolog("ERROR");
        return 1;
    }
    blogpayload = httpservererror;
    bloghtml.close();
    sendtolog("ERROR");
    return 1;
}

int loadloginHTMLintoram() {
    std::string templine;
    std::ifstream loginhtml;
    loginpayload = "";
    loginhtml.open(loginhtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (loginhtml.is_open() == true) {
        while (completionht != true) {
            getline(loginhtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                loginpayload = loginpayload + templine + "\n";
            }
        }
        // Connection: close\r\n
        std::string beforepayload = "\n\n";
        int length = loginpayload.length();
        loginpayload = httpsuccess + std::to_string(length) + beforepayload + loginpayload;
        loginhtml.close();
        sendtolog("Done");
        return 0;
    } else {
        loginpayload = httpservererror;
        loginhtml.close();
        sendtolog("ERROR");
        return 1;
    }
    loginpayload = httpservererror;
    loginhtml.close();
    sendtolog("ERROR");
    return 1;
}

int loadsignupHTMLintoram() {
    std::string templine;
    std::ifstream signuphtml;
    signuppayload = "";
    signuphtml.open(signuphtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (signuphtml.is_open() == true) {
        while (completionht != true) {
            getline(signuphtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                signuppayload = signuppayload + templine + "\n";
            }
        }
        std::string beforepayload = "\n\n";
        int length = signuppayload.length();
        signuppayload = httpsuccess + std::to_string(length) + beforepayload + signuppayload;
        signuphtml.close();
        sendtolog("Done");
        return 0;
    } else {
        loginpayload = httpservererror;
        signuphtml.close();
        sendtolog("ERROR");
        return 1;
    }
    loginpayload = httpservererror;
    signuphtml.close();
    sendtolog("ERROR");
    return 1;
}

int loadgetstartedHTMLintoram() {
    std::string templine;
    std::ifstream getstartedstream;
    getstartedpayload = "";
    getstartedstream.open(getstartedfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (getstartedstream.is_open() == true) {
        while (completionht != true) {
            getline(getstartedstream, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                getstartedpayload = getstartedpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = getstartedpayload.length();
        getstartedpayload = httpsuccess + std::to_string(length) + beforepayload + getstartedpayload;
        getstartedstream.close();
        sendtolog("Done");
        return 0;
    } else {
        getstartedpayload = httpservererror;
        getstartedstream.close();
        sendtolog("ERROR");
        return 1;
    }
    getstartedpayload = httpservererror;
    getstartedstream.close();
    sendtolog("ERROR");
    return 1;
}

int loadaccountHTMLintoram() {
    std::string templine;
    std::ifstream accountpayloadfile;
    accountpayload = "";
    accountpayloadfile.open(accountfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (accountpayloadfile.is_open() == true) {
        while (completionht != true) {
            getline(accountpayloadfile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                accountpayload = accountpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = accountpayload.length();
        accountpayload = httpsuccess + std::to_string(length) + beforepayload + accountpayload;
        accountpayloadfile.close();
        sendtolog("Done");
        return 0;
    } else {
        accountpayload = httpservererror;
        accountpayloadfile.close();
        sendtolog("ERROR");
        return 1;
    }
    accountpayload = httpservererror;
    accountpayloadfile.close();
    sendtolog("ERROR");
    return 1;
}

int loadinstallHTMLintoram() {
    std::string templine;
    std::ifstream installHTMLFile;
    installhtmlpayload = "";
    installHTMLFile.open(installfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (installHTMLFile.is_open() == true) {
        while (completionht != true) {
            getline(installHTMLFile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                installhtmlpayload = installhtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = installhtmlpayload.length();
        installhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + installhtmlpayload;
        installHTMLFile.close();
        sendtolog("Done");
        return 0;
    } else {
        installhtmlpayload = httpservererror;
        installHTMLFile.close();
        sendtolog("ERROR");
        return 1;
    }
    installhtmlpayload = httpservererror;
    installHTMLFile.close();
    sendtolog("ERROR");
    return 1;
}

int loadinstallscriptSHHTMLintoram() {
    std::string templine;
    std::ifstream installSHFile;
    installscriptSHpayload = "";
    installSHFile.open(installBASH);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (installSHFile.is_open() == true) {
        while (completionht != true) {
            getline(installSHFile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                installscriptSHpayload = installscriptSHpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = installscriptSHpayload.length();
        installscriptSHpayload = httpsuccess + std::to_string(length) + beforepayload + installscriptSHpayload;
        installSHFile.close();
        sendtolog("Done");
        return 0;
    } else {
        installscriptSHpayload = httpservererror;
        installSHFile.close();
        sendtolog("ERROR");
        return 1;
    }
    installscriptSHpayload = httpservererror;
    installSHFile.close();
    sendtolog("ERROR");
    return 1;
}

int loadHTMLINTORAM() {
    loginfo("HTML - Loading All Main HTML Pages into RAM!", true);
    int returnvalue = 0;
    loginfo("HTML - Loading index.html into RAM...", false);
    returnvalue = returnvalue + loadmainHTMLintoram();
    loginfo("HTML - Loading pricing.html into RAM...", false);
    returnvalue = returnvalue + loadpricingHTMLintoram();
    loginfo("HTML - Loading blog.html into RAM...", false);
    returnvalue = returnvalue + loadblogHTMLintoram();
    loginfo("HTML - Loading login.html into RAM...", false);
    returnvalue = returnvalue + loadloginHTMLintoram();
    loginfo("HTML - Loading signup.html into RAM...", false);
    returnvalue = returnvalue + loadsignupHTMLintoram();
    loginfo("HTML - Loading getstarted.html into RAM...", false);
    returnvalue = returnvalue + loadgetstartedHTMLintoram();
    loginfo("HTML - Loading account.html into RAM...", false);
    returnvalue = returnvalue + loadaccountHTMLintoram();
    loginfo("HTML - Loading install.html into RAM...", false);
    returnvalue = returnvalue + loadinstallHTMLintoram();
    loginfo("HTML - Loading installscript.sh into RAM...", false);
    returnvalue = returnvalue + loadinstallscriptSHHTMLintoram();

    // returnvalue = returnvalue + 
    loginfo("HTML - Finishing Loading into RAM...", false);

    if (returnvalue != 0) {
        sendtolog("ERROR");
        logwarning("HTML - LOADING INTO RAM RETURNED VALUE - ", false);
        sendtologopen(std::to_string(returnvalue));
        sendtolog(" - CONTINUING");
    } else {
        sendtolog("DONE");
    }
    return 0;
}



// TEMPORARY READS
std::string readTOSFree() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSFreefilefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readTOSPro() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSProfilefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readTOSEnterprise() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSEnterprisefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readPrivacyPolicy() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(PrivacyPolicyfile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}





//////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (443) - MAIN HTTPS SERVER!! //
//////////////////////////////////////////////////////////////
void httpsconnectionthread(SSL *ssl, char client_ip[INET_ADDRSTRLEN], int client_fd, struct sockaddr_in client_addr) {
    loginfo("HTTPS THREAD", true);
    std::string ipaddr;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "/certs/server.crt", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "/certs/private.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return;
    }

    loginfo("True through ssl checks", true);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        logwarning("SSL_ACCEPT NOT TRUE!", true);
    } else {
        // Buffer to read the incoming request
        char buffer[2048] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        int timer89 = 0;
//        logwarning(buffer, true);
        int timer89max = 5;
        bool completed23 = false;
        if (buffer != "" && sizeof(buffer) >= 7) {
            std::string bufferstring = buffer;
            std::string headerrequest = bufferstring.substr(0,4);
            
            if (bufferstring.length() >= 7) {
                // CHANGE HERE FROM GET: / TO GET /
                logcritical(headerrequest, true);
                if (headerrequest == "GET ") {
                    std::string maindirectory = bufferstring.substr(4,1);

                    // MAKE SURE THAT THE ADDRESS IS VALID
                    if (maindirectory == "/") {
                        std::string nextletter = bufferstring.substr(5,2);

                        // MAKE SURE A CONNECTION WAS RECEIVED!
                        bool pagefound = false;

                        // MAIN PAGE
                        if (nextletter == " H") {
                            int send_res = SSL_write(ssl, mainhtmlpayload.c_str(),mainhtmlpayload.length());
                            //int send_res=send(new_socket,mainhtmlpayload.c_str(),mainhtmlpayload.length(),0);
                            pagefound = true;
                        }

                        // INDEX.HTML
                        if (nextletter == "in") {
                            //index.html
                            std::string indexfulldictionary = bufferstring.substr(5, 10);
                            if (indexfulldictionary == "index.html") {
                                int send_res=SSL_write(ssl,mainhtmlpayload.c_str(),mainhtmlpayload.length());
                                pagefound = true;
                            }
                        }

                        // PRICING.HTML
                        if (nextletter == "pr") {
                            // pricing.html
                            std::string pricingfulldictionary = bufferstring.substr(5,12);
                            if (pricingfulldictionary == "pricing.html") {
                                int send_res=SSL_write(ssl,pricinghtmlpayload.c_str(),pricinghtmlpayload.length());
                                pagefound = true;
                            }
                        }

                        // BLOG.HTML
                        if (nextletter == "bl") {
                            // blog.html
                            std::string blogfulldictionary = bufferstring.substr(5,9);
                            if (blogfulldictionary == "blog.html") {
                                int send_res=SSL_write(ssl,blogpayload.c_str(),blogpayload.length());
                                pagefound = true;
                            }
                        }

                        // LOGIN.HTML
                        if (nextletter == "lo") {
                            // login.html
                            std::string loginfulldictionary = bufferstring.substr(5,10);
                            if (loginfulldictionary == "login.html") {
                                int send_res=SSL_write(ssl,loginpayload.c_str(),loginpayload.length());
                                pagefound = true;
                            }
                        }

                        // TERMS OF SERVICE
                        if (nextletter == "TO") {
                            // TOSFree.html
                            // TOSPro.html
                            // TOSEnterprise.html
                            std::string TOSfulldictionary = bufferstring.substr(5, 11);

                            // TOSFREE.HTML
                            if (TOSfulldictionary == "TOSFree.htm") {
                                std::string tospayload = readTOSFree();
                                int send_res=SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }

                            // TOSPRO.HTML
                            if (TOSfulldictionary == "TOSPro.html") {
                                std::string tospayload = readTOSPro();
                                int send_res=SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }

                            // TOSEnterpri
                            if (TOSfulldictionary == "TOSEnterpri") {
                                std::string tospayload = readTOSEnterprise();
                                int send_res=SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }
                        }

                        // PRIVACY POLICY
                        if (nextletter == "pr") {
                            // privacypolicy.html
                            std::string privacyfulldictionary = bufferstring.substr(5,18);
                            if (privacyfulldictionary == "privacypolicy.html") {
                                std::string tospayload = readPrivacyPolicy();
                                int send_res=SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }
                        }

                        // GET-STARTED.HTML
                        if (nextletter == "ge") {
                            // GET-STARTED.HTML
                            std::string getstartedfulldictionary = bufferstring.substr(5,16);
                            if (getstartedfulldictionary == "get-started.html") {
                                int send_res=SSL_write(ssl,getstartedpayload.c_str(),getstartedpayload.length());
                                pagefound = true;
                            }
                        }



                        // NONE IS TRUE
                        if (pagefound != true) {
                            int send_res=SSL_write(ssl,httpnotfound.c_str(),httpnotfound.length());
                        }
                    }
                } else {
                    if (headerrequest == "POST") {
                        if (bufferstring.length() >= 115) {
                            int timey9000 = 0;
                            int timey9000max = 50;
                            bool completionah = false;
                            int dashesreceived = 0;
                            std::string microstring = "";
                            std::string headerstringpost = "";
                            int micronumber = 4;
                            bool pagefoundpost = false;

                            while(timey9000 <= timey9000max && completionah == false) {
                                micronumber = micronumber + 1;
                                timey9000 = timey9000 + 1;
                                microstring = bufferstring.substr(micronumber, 1);
                                loginfo(microstring, true);
                                if (microstring != "H" && microstring != "/" && microstring != " ") {
                                    if (dashesreceived > 0) {
                                        headerstringpost = headerstringpost + microstring;
                                    }
                                }

                                if (microstring == "H") {
                                    completionah = true;
                                }

                                if (microstring == "/") {
                                    dashesreceived = dashesreceived + 1;
                                }
                            }

                            sendtologopen("ENOUGH!~");
                            sendtolog(headerstringpost);

                            // LOGINTOACCOUNT
                            if (headerstringpost == "logintoaccount") {
                                loginfo("logintoaccount received", true);
                                pagefoundpost = true;
                                int offset = 0;
                                bool completedlp = false;
                                int timey809 = 0;
                                int timey809max = 100;
                                std::string microswisscode = "";
                                std::string jsonlogin = "";
                                int bufferstringlength = bufferstring.length();

                                while(completedlp == false && timey809 <= timey809max) {
                                    microswisscode = bufferstring.substr(bufferstringlength - offset - 1, 1);
                                    offset = offset + 1;
                                    if (microswisscode == "{") {
                                        jsonlogin = bufferstring.substr(bufferstringlength - offset, bufferstringlength - offset - 1);
                                    } else {
                                        timey809 = timey809 + 1;
                                    }
                                }

                                if (jsonlogin != "") {
                                    // ADD MARIADB CHECK
                                    loginfo(jsonlogin, true);

                                    // GO AHEAD TO ANALYZE JSON AND SEND IT TO MARIADB TO VERIFY
                                    std::string userstringverify = jsonlogin.substr(2,8);
                                    debugout(userstringverify);
                                    if (userstringverify == "username"){
                                        std::string verifyjson = jsonlogin.substr(11,1);
                                        int analyzenumber = 12;
                                        debugout(verifyjson);
                                        if (verifyjson == ":") {
                                            int timering80 = 0;
                                            int timering80max = 80;
                                            bool timering80set = false;
                                            int quotations = 0;
                                            int characternumber = 0;
                                            std::string hellostring = "";
                                            std::string username = "";
                                            while (timering80 <= timering80max && timering80set != true && quotations < 2) {
                                                debugout(hellostring);
                                                hellostring = jsonlogin.substr(analyzenumber, 1);
                                                if (hellostring.find('"') != std::string::npos) {
                                                    quotations = quotations + 1;
                                                    if (quotations > 1) {
                                                        timering80set = true;
                                                    }
                                                } else {
                                                    if (quotations == 1) {
                                                        username = username + hellostring;
                                                    }
                                                }
                                                analyzenumber = analyzenumber + 1;
                                                timering80 = timering80 + 1;
                                            }

                                            hellostring = jsonlogin.substr(analyzenumber, 1);
                                            analyzenumber = analyzenumber + 1;
                                            debugout(hellostring);

                                            if (hellostring == ",") {
                                                // WORK ON VERIFYING PASSWORD
                                                int timering90 = 0;
                                                int timering90max = 64;
                                                bool timering90set = false;
                                                int quotations2 = false;
                                                int characternumber = 0;
                                                analyzenumber = analyzenumber + 11;
                                                std::string password = "";
                                                while (timering90 <= timering90max && timering90set != true && quotations2 < 2) {
                                                    hellostring = jsonlogin.substr(analyzenumber, 1);
                                                    debugout(hellostring);
                                                    if (hellostring.find('"') != std::string::npos) {
                                                        quotations2 = quotations2 + 1;
                                                        if (quotations2 > 1) {
                                                            timering90set = true;
                                                        }
                                                    } else {
                                                        if (quotations2 == 1) {
                                                            password = password + hellostring;
                                                        }
                                                    }
                                                    analyzenumber = analyzenumber + 1;
                                                    timering90 = timering90 + 1;
                                                }

                                                std::cout << "RECEIVED CREDENTIALS user=" << username <<", pass=" << password << ";" << std::endl;
                                                bool verified = mariadbVALIDATE_USER(username, password);
                                                std::cout << "RECEIVED VERIFIED STATUS OF " << verified << std::endl;
                                                if (verified == true) {
                                                    // CREATE SESSION TOKEN AND REDIRECT
                                                    loginfo("SENDING TO ACCOUNT PAGE", true);
                                                    std::string sessiontoken = generateRandomClientKey();
                                                    mariadbINSERT_SESSIONKEY(username, sessiontoken);
                                                    sleep(1);
                                                    int contentlength = 0;
                                                    char doublequote = '"';
                                                    // SEND MODIFIED JSON WITH SUCCESS, CLIENT TOKEN, AND ADDRESS TO FORWARD TO...
                                                    std::string sendpayloadforlength = std::string("{") + doublequote + std::string("state") + doublequote + ":" + doublequote + "ok" + doublequote + "," + doublequote + "token" + doublequote + ":" + doublequote + sessiontoken + doublequote + "," + doublequote + "redirect" + doublequote + ":" + doublequote + "account.html" + doublequote + "}";
                                                    contentlength = sendpayloadforlength.length();
                                                    std::string sendpayloadtoclient = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(contentlength) + "\r\n" + "\r\n" + sendpayloadforlength;
                                                    sendtolog("SENDING TO CLIENT...");
                                                    int send_res=SSL_write(ssl, sendpayloadtoclient.c_str(), sendpayloadtoclient.length());
                                                    if (send_res <= 0) {
                                                        // Log a critical error message
                                                        logcritical("AN ERROR OCCURRED SENDING SESSION TOKEN!", true);
                                                        // Determine the specific SSL error using SSL_get_error
                                                        int ssl_error_code = SSL_get_error(ssl, send_res);
                                                        switch (ssl_error_code) {
                                                            case SSL_ERROR_WANT_WRITE:
                                                                logcritical("SSL_ERROR_WANT_WRITE: The operation did not complete, try again later.", true);
                                                                break;
                                                            case SSL_ERROR_WANT_READ:
                                                                logcritical("SSL_ERROR_WANT_READ: The operation did not complete, try to read more data.", true);
                                                                break;
                                                            case SSL_ERROR_SYSCALL:
                                                                logcritical("SSL_ERROR_SYSCALL: A system call error occurred.", true);
                                                                break;
                                                            case SSL_ERROR_SSL:
                                                                logcritical("SSL_ERROR_SSL: A failure occurred in the SSL library.", true);
                                                                break;
                                                            default:
                                                                logcritical("Unknown SSL error occurred.", true);
                                                        }
                                                        // Print additional detailed error messages from OpenSSL's error queue
                                                        unsigned long err_code;
                                                        while ((err_code = ERR_get_error()) != 0) {
                                                            char err_buf[256];
                                                            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                                                            logcritical(std::string("SSL Error: ") + err_buf, true); // Log each SSL error
                                                        }
                                                    } else {
                                                        // Log the successful send operation
                                                        sendtologopen("Sent Payload: ");
                                                        sendtolog(sendpayloadtoclient);
                                                    }
                                                } else {
                                                    int contentlength = 0;
                                                    char doublequote = '"';
                                                    // SEND MODIFIED JSON WITH SUCCESS, CLIENT TOKEN, AND ADDRESS TO FORWARD TO...
                                                    std::string sendpayloadforlength = std::string("{") + doublequote + std::string("state") + doublequote + ":" + doublequote + "wrongpass" + doublequote + "}";
                                                    contentlength = sendpayloadforlength.length();
                                                    std::string sendpayloadtoclient = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(contentlength) + "\r\n" + "\r\n" + sendpayloadforlength;
                                                    sendtolog("SENDING TO CLIENT...");
                                                    int send_res=SSL_write(ssl, sendpayloadtoclient.c_str(), sendpayloadtoclient.length());
                                                    if (send_res <= 0) {
                                                        // Log a critical error message
                                                        logcritical("AN ERROR OCCURRED SENDING FAIL MESSAGE!", true);
                                                        // Determine the specific SSL error using SSL_get_error
                                                        int ssl_error_code = SSL_get_error(ssl, send_res);
                                                        switch (ssl_error_code) {
                                                            case SSL_ERROR_WANT_WRITE:
                                                                logcritical("SSL_ERROR_WANT_WRITE: The operation did not complete, try again later.", true);
                                                                break;
                                                            case SSL_ERROR_WANT_READ:
                                                                logcritical("SSL_ERROR_WANT_READ: The operation did not complete, try to read more data.", true);
                                                                break;
                                                            case SSL_ERROR_SYSCALL:
                                                                logcritical("SSL_ERROR_SYSCALL: A system call error occurred.", true);
                                                                break;
                                                            case SSL_ERROR_SSL:
                                                                logcritical("SSL_ERROR_SSL: A failure occurred in the SSL library.", true);
                                                                break;
                                                            default:
                                                                logcritical("Unknown SSL error occurred.", true);
                                                        }
                                                        // Print additional detailed error messages from OpenSSL's error queue
                                                        unsigned long err_code;
                                                        while ((err_code = ERR_get_error()) != 0) {
                                                            char err_buf[256];
                                                            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                                                            logcritical(std::string("SSL Error: ") + err_buf, true); // Log each SSL error
                                                        }
                                                    } else {
                                                        // Log the successful send operation
                                                        sendtologopen("Sent Payload: ");
                                                        sendtolog(sendpayloadtoclient);
                                                    }
                                                }
                                            } else {
                                                int send_res=SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                            }
                                        } else {
                                            int send_res=SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                        }
                                    } else {
                                        int send_res=SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                    }
                                    
                                } else {
                                    int send_res=SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                }
                            } 

                            // CREATENEWACCOUNT
                            if (headerstringpost == "createnewaccount") {
                                pagefoundpost = true;
                            }



                            if (pagefoundpost != true) {
                                int send_res=SSL_write(ssl,httpfail.c_str(),httpfail.length());
                            }
                        } else {
                            sendtolog("ERROR OCCURED, dATA NOT LONG ENOUGH");
                            int send_res=SSL_write(ssl,httpfail.c_str(),httpfail.length());
                        }                        
                    } else {
                        int send_res=SSL_write(ssl,httpfail.c_str(),httpfail.length());
                    }
                }
            } else {
                int send_res=SSL_write(ssl,httpfail.c_str(),httpfail.length());
            }
        } else {
            // FUTURE TERMINATE COMMAND
            int send_res=SSL_write(ssl,httpfail.c_str(),httpfail.length());
        }
        
    } 
    close(client_fd);
    return;
    //sleep(600);
    //mariadb_REMOVEPACKETFROMIPADDR(ipaddr);
} 

void handleConnections443(int server_fd) {

    port443runningstatus = true;
    int threadnumber = 0;    
    static bool initialized = false;
    char buffer[2048] = {0};
    struct sockaddr_in address, client_addr;
    socklen_t addrlen = sizeof(address);
    SSL *ssl;
    char client_ip[INET_ADDRSTRLEN];
    int checks = 0;
    int allowed = 0;
    socklen_t client_addr_len = sizeof(client_addr);

    if (!initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        initialized = true;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "/certs/server.crt", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "/certs/private.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        logcritical("THE PRIVATE KEY DOES NOT MATCH THE PUBLIC CERTIFICATE!", true);
        SSL_CTX_free(ctx);
        return;
    }
    loginfo("Started!", true);

    // && stopSIGNAL.load() == 0
    while (port443runningstatus == true) {
        
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
       
        if (client_fd < 0) {
            if (client_fd == -1) {
                sleep(0.5);
                if (stopSIGNAL.load() == true) {
                    port443runningstatus = false;
                }
            } else {
                loginfo("UNABLE TO ACCEPT HTTPS CONNECTION", true);
                SSL_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
        } else {
            ssl = SSL_new(ctx);
            if (!ssl) {
                ERR_print_errors_fp(stderr);
                close(client_fd);
                SSL_CTX_free(ctx);
                return;
            }
            SSL_set_fd(ssl, client_fd);

            loginfo("heyheyhey", true);

            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            loginfo("Connection from: ", false);
            sendtolog(client_ip);
            std::string clientipstd = client_ip;

            if (clientipstd == "172.17.0.1") {
                //loginfo("P443 - RECEIVED LOCALHOST REQUEST, IGNORING...", false);
                //sendtolog(clientipstd);
                return;
            }

            // FIX THIS
            //int allowed = mariadb_CHECKIPADDR(client_ip);
            int allowed = 0;

            if (allowed == 255) {
                mariadb_ADDIPADDR(client_ip);
            }

            if (allowed == 0 || allowed == 255) {
                // ANTI-CRASH PACKET FLOW CHECK
                if (timers[1] == time(NULL)) {
                    packetspam = packetspam + 1;
                    if (packetspam >= 10) {
                        // STOP CONNECTIONS/ENTER BLOCKING STATE
                        waiting230 = true;
                        logwarning("LOCKING HTTPS PORT FOR NOW (PACKET SPAM)", true);
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
                    logwarning("ALLOWING RESTART OF HTTP PROCESS!", true);
                }

                if (waiting230 == false) { 
                    // SWITCH OF 30 CONSECUTIVE THREADS FOR HTTPS (443)
                    switch (threadnumber) {
                        case 0: {
                            std::thread threadnametrigger00(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger00.detach();
                            break;
                        }
                        case 1: {
                            std::thread threadnametrigger01(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger01.detach();
                            break;
                        }
                        case 2: {
                            std::thread threadnametrigger02(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger02.detach();
                            break;
                        }
                        case 3: {
                            std::thread threadnametrigger03(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger03.detach();
                            break;
                        }
                        case 4: {
                            std::thread threadnametrigger04(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger04.detach();
                            break;
                        }
                        case 5: {
                            std::thread threadnametrigger05(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger05.detach();
                            break;
                        }
                        case 6: {
                            std::thread threadnametrigger06(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger06.detach();
                            break;
                        }
                        case 7: {
                            std::thread threadnametrigger07(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger07.detach();
                            break;
                        }
                        case 8: {
                            std::thread threadnametrigger08(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger08.detach();
                            break;
                        }
                        case 9: {
                            std::thread threadnametrigger09(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger09.detach();
                            break;
                        }
                        case 10: {
                            std::thread threadnametrigger10(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger10.detach();
                            break;
                        }
                        case 11: {
                            std::thread threadnametrigger11(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger11.detach();
                            break;
                        }
                        case 12: {
                            std::thread threadnametrigger12(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger12.detach();
                            break;
                        }
                        case 13: {
                            std::thread threadnametrigger13(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger13.detach();
                            break;
                        }
                        case 14: {
                            std::thread threadnametrigger14(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger14.detach();
                            break;
                        }
                        case 15: {
                            std::thread threadnametrigger15(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger15.detach();
                            break;
                        }
                        case 16: {
                            std::thread threadnametrigger16(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger16.detach();
                            break;
                        }
                        case 17: {
                            std::thread threadnametrigger17(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger17.detach();
                            break;
                        }
                        case 18: {
                            std::thread threadnametrigger18(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger18.detach();
                            break;
                        }
                        case 19: {
                            std::thread threadnametrigger19(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger19.detach();
                            break;
                        }
                        case 20: {
                            std::thread threadnametrigger20(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger20.detach();
                            break;
                        }
                        case 21: {
                            std::thread threadnametrigger21(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger21.detach();
                            break;
                        }
                        case 22: {
                            std::thread threadnametrigger22(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger22.detach();
                            break;
                        }
                        case 23: {
                            std::thread threadnametrigger23(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger23.detach();
                            break;
                        }
                        case 24: {
                            std::thread threadnametrigger24(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger24.detach();
                            break;
                        }
                        case 25: {
                            std::thread threadnametrigger25(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger25.detach();
                            break;
                        }
                        case 26: {
                            std::thread threadnametrigger26(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger26.detach();
                            break;
                        }
                        case 27: {
                            std::thread threadnametrigger27(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger27.detach();
                            break;
                        }
                        case 28: {
                            std::thread threadnametrigger28(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger28.detach();
                            break;
                        }
                        case 29: {
                            std::thread threadnametrigger29(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger29.detach();
                            break;
                        }
                        case 30: {
                            std::thread threadnametrigger30(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger30.detach();
                            break;
                        }
                        case 31: {
                            std::thread threadnametrigger31(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger31.detach();
                            break;
                        }
                        case 32: {
                            std::thread threadnametrigger32(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger32.detach();
                            break;
                        }
                        case 33: {
                            std::thread threadnametrigger33(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger33.detach();
                            break;
                        }
                        case 34: {
                            std::thread threadnametrigger34(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger34.detach();
                            break;
                        }
                        case 35: {
                            std::thread threadnametrigger35(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger35.detach();
                            break;
                        }
                        case 36: {
                            std::thread threadnametrigger36(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger36.detach();
                            break;
                        }
                        case 37: {
                            std::thread threadnametrigger37(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger37.detach();
                            break;
                        }
                        case 38: {
                            std::thread threadnametrigger38(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger38.detach();
                            break;
                        }
                        case 39: {
                            std::thread threadnametrigger39(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger39.detach();
                            break;
                        }
                        case 40: {
                            std::thread threadnametrigger40(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger40.detach();
                            break;
                        }
                        case 41: {
                            std::thread threadnametrigger41(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger41.detach();
                            break;
                        }
                        case 42: {
                            std::thread threadnametrigger42(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger42.detach();
                            break;
                        }
                        case 43: {
                            std::thread threadnametrigger43(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger43.detach();
                            break;
                        }
                        case 44: {
                            std::thread threadnametrigger44(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger44.detach();
                            break;
                        }
                        case 45: {
                            std::thread threadnametrigger45(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger45.detach();
                            break;
                        }
                        case 46: {
                            std::thread threadnametrigger46(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger46.detach();
                            break;
                        }
                        case 47: {
                            std::thread threadnametrigger47(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger47.detach();
                            break;
                        }
                        case 48: {
                            std::thread threadnametrigger48(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger48.detach();
                            break;
                        }
                        case 49: {
                            std::thread threadnametrigger49(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger49.detach();
                            break;
                        }
                    }
                    if (threadnumber == 49) {
                        threadnumber = 0;
                    } else {
                        threadnumber = threadnumber + 1;
                    }
                }
            }
        }   
    }

    loginfo("P443 - Shutting Down...", true);
    return;
}


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

    // WHILE RUNNING LOOP FOR HTTP, WAITING FOR CLIENTS TO CONNECT
    while (true) {
        int client_fd = accept(server_fd23, (struct sockaddr*)&address, &addrlen);

        if (client_fd < 0) {
            logcritical("UNABLE TO ACCEPT CONNECTION (80)", true);
        } else {
            // Simple HTTP response for redirection
            const std::string response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://" + serveraddress + "/ \r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

            // Send the redirect response
            send(client_fd, response.c_str(), response.length(), 0);
            close(client_fd);
        }
    }
    close(server_fd23);
}





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

    // MAIN HEADER RELATING TO HONEYPOT/HONEYPI CONNECTIONS
    if (header1 == "CONNECTION") {
        // MAIN CONNECTION FOR NEW HONEYPIS
        if (data1 == "NEW") {
            // ADD CONDITIONS BASED ON SERVER STATUS AND OTHER THINGS
            // int send_res=send(clientID,apireject.c_str(),apireject.length(),0);
            int updatesig = updateSIGNAL.load();
            int stopsig = stopSIGNAL.load();
            int statusPort = statusP11829.load();

            if (updatesig == 0 && stopsig == 0 && statusPort == 0) {
                int send_res=send(clientID,apiavailable.c_str(),apiavailable.length(),0);
            } else {
                int send_res=send(clientID,apiunavailable.c_str(),apiunavailable.length(),0);
            }
        }

        // ESTABLISH CONNECTION AND VERIFY API KEYS; CREATE NEW TOKEN KEYS
        if (data1 == "ESTABLISH") {

        }

        // CHECK FOR UPDATES SCRIPT
        if (data1 == "CHECK_FOR_UPDATE") {

        }

        // UPDATE IP LIST AND SEND TO CLIENT
        if (data1 == "UPDATE") {

        }

        // REPORT HONEYPOT CONNECTED CORRECTLY TO INTERNET
        if (data1 == "REPORT") {

        }

        // HONEYPOT SENDING REPORT TO SERVER
        if (data1 == "NEW_REPORT") {

        }

        // HONEYPOT IN MIDDLE OF SENDING LARGE HACKER REPORT
        if (data1 == "REPORT_PART") {
            
        }
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
                        previousmarker = previousmarker + 2;
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
                        previousmarker = previousmarker + 2;
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

void apiconnectionthread(int clientID) {
    char buffer[16384] = {0};
    read(clientID, buffer, 16384);
    sendtolog(buffer);
    std::string bufferstd = buffer;

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
                    if (bufferstd.substr(10,22) == "Content-Type:text/json") {
                        sendtolog("THIS WORKS");
                        std::string messagetoread = bufferstd.substr(34, bufferstd.length() - 34);
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

void handle11829Connections(int server_fd4, int clientID) {
    api11829 = true;
    int apithreadnumber = 0;
    while(api11829 == true) {
        char buffer[2048] = {0};
        struct sockaddr_in address;
        socklen_t addrlen = sizeof(address);
        int new_socket2;
        ssize_t valread;
        std::string hello = "Hello from server";

        port11829runningstatus = true;
        struct sockaddr_in client_addr;

        socklen_t client_addr_len = sizeof(client_addr);

        int clientID = accept(server_fd4, (struct sockaddr*)&client_addr, &client_addr_len);

        if (clientID < 0) {
            // NOTHING
        } else {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "Connection from: " << client_ip << '\n';
            std::string clientipstd = client_ip;
            int checks = 0;
            int allowed = 0;
            allowed = mariadb_CHECKIPADDR(client_ip);

            if (allowed == true) {
                loginfo("11829 port initialized", true);
                switch (apithreadnumber) {
                    case 0: {
                        std::thread apithreadnumber00(apiconnectionthread, clientID);
                        apithreadnumber00.detach();
                        break;
                    }
                    case 1: {
                        std::thread apithreadnumber01(apiconnectionthread, clientID);
                        apithreadnumber01.detach();
                        break;
                    }
                    case 2: {
                        std::thread apithreadnumber02(apiconnectionthread, clientID);
                        apithreadnumber02.detach();
                        break;
                    }
                    case 3: {
                        std::thread apithreadnumber03(apiconnectionthread, clientID);
                        apithreadnumber03.detach();
                        break;
                    }
                    case 4: {
                        std::thread apithreadnumber04(apiconnectionthread, clientID);
                        apithreadnumber04.detach();
                        break;
                    }
                    case 5: {
                        std::thread apithreadnumber05(apiconnectionthread, clientID);
                        apithreadnumber05.detach();
                        break;
                    }
                    case 6: {
                        std::thread apithreadnumber06(apiconnectionthread, clientID);
                        apithreadnumber06.detach();
                        break;
                    }
                    case 7: {
                        std::thread apithreadnumber07(apiconnectionthread, clientID);
                        apithreadnumber07.detach();
                        break;
                    }
                    case 8: {
                        std::thread apithreadnumber08(apiconnectionthread, clientID);
                        apithreadnumber08.detach();
                        break;
                    }
                    case 9: {
                        std::thread apithreadnumber09(apiconnectionthread, clientID);
                        apithreadnumber09.detach();
                        break;
                    }
                    case 10: {
                        std::thread apithreadnumber10(apiconnectionthread, clientID);
                        apithreadnumber10.detach();
                        break;
                    }
                    case 11: {
                        std::thread apithreadnumber11(apiconnectionthread, clientID);
                        apithreadnumber11.detach();
                        break;
                    }
                    case 12: {
                        std::thread apithreadnumber12(apiconnectionthread, clientID);
                        apithreadnumber12.detach();
                        break;
                    }
                    case 13: {
                        std::thread apithreadnumber13(apiconnectionthread, clientID);
                        apithreadnumber13.detach();
                        break;
                    }
                    case 14: {
                        std::thread apithreadnumber14(apiconnectionthread, clientID);
                        apithreadnumber14.detach();
                        break;
                    }
                    case 15: {
                        std::thread apithreadnumber15(apiconnectionthread, clientID);
                        apithreadnumber15.detach();
                        break;
                    }
                    case 16: {
                        std::thread apithreadnumber16(apiconnectionthread, clientID);
                        apithreadnumber16.detach();
                        break;
                    }
                    case 17: {
                        std::thread apithreadnumber17(apiconnectionthread, clientID);
                        apithreadnumber17.detach();
                        break;
                    }
                    case 18: {
                        std::thread apithreadnumber18(apiconnectionthread, clientID);
                        apithreadnumber18.detach();
                        break;
                    }
                    case 19: {
                        std::thread apithreadnumber19(apiconnectionthread, clientID);
                        apithreadnumber19.detach();
                        break;
                    }
                    case 20: {
                        std::thread apithreadnumber20(apiconnectionthread, clientID);
                        apithreadnumber20.detach();
                        break;
                    }
                    case 21: {
                        std::thread apithreadnumber21(apiconnectionthread, clientID);
                        apithreadnumber21.detach();
                        break;
                    }
                    case 22: {
                        std::thread apithreadnumber22(apiconnectionthread, clientID);
                        apithreadnumber22.detach();
                        break;
                    }
                    case 23: {
                        std::thread apithreadnumber23(apiconnectionthread, clientID);
                        apithreadnumber23.detach();
                        break;
                    }
                    case 24: {
                        std::thread apithreadnumber24(apiconnectionthread, clientID);
                        apithreadnumber24.detach();
                        break;
                    }
                    case 25: {
                        std::thread apithreadnumber25(apiconnectionthread, clientID);
                        apithreadnumber25.detach();
                        break;
                    }
                    case 26: {
                        std::thread apithreadnumber26(apiconnectionthread, clientID);
                        apithreadnumber26.detach();
                        break;
                    }
                    case 27: {
                        std::thread apithreadnumber27(apiconnectionthread, clientID);
                        apithreadnumber27.detach();
                        break;
                    }
                    case 28: {
                        std::thread apithreadnumber28(apiconnectionthread, clientID);
                        apithreadnumber28.detach();
                        break;
                    }
                    case 29: {
                        std::thread apithreadnumber29(apiconnectionthread, clientID);
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
                int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
            }

 //        Send a hello message to the client
         send(new_socket2, hello.c_str(), hello.size(), 0);
         std::cout << "Hello message sent" << std::endl;
        }
    }
}




//////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (11830) //
//////////////////////////////////////////
void handle11830Connections(int server_fd11830) {
    api11830 = true;
    while(api11830 == true) {
        char buffer[2048] = {0};
        struct sockaddr_in address11830;
        socklen_t addrlen11830 = sizeof(address11830);
        int new_socket11830;
        ssize_t valread11830;
        std::string hello11830 = "Hello from server";
    //   socklen_t client_addr_len = sizeof(client_addr);

        if ((new_socket11830 = accept(server_fd11830, (struct sockaddr*)&address11830, &addrlen11830)) < 0) {
            logcritical("UNABLE TO ACCEPT CONNECTION (11830)", true);
            exit(EXIT_FAILURE);
        } else {
            loginfo("11830 port initialized", true);
        }

    
 //       std::fill_n(buffer, 2048, "");
//        char client_ip[INET_ADDRSTRLEN];
 //       inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        read(new_socket11830, buffer, 2048);
        sendtologopen(buffer);
        std::string bufferstd = buffer;

        if (bufferstd.length() >= 5) {
            std::string keysubstring = "";
            std::string bufferedkeystring = "";
            std::string unencryptedstring = "";
            keysubstring = bufferstd.substr(0,5);
        } else {

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
         send(new_socket2, hello11830.c_str(), hello11830.size(), 0);
         std::cout << "Hello message sent" << std::endl;
    }
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
    sendtologopen("...");
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
    sendtolog("Server by Matthew Whitworth (MawWebby)");
    sendtolog("Version: " + honeyversion);
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");
    sendtolog("");

    // DELAY FOR SYSTEM TO START FURTHER (FIGURE OUT CURRENT TIME)
    sleep(0.5);


    // BETA SCRIPTS
 //   mariadbPIAPI_keyvalid("PIlws9pNqJ4olvnNTHxyvYhRD8WM1158N1Zlo308UVtqEv0ihWxLCN94Uxx07r1n");
 //   mariadbROUTERAPIkeyvalid("ROdgkrvMvuHGL86dGHI65va3Ss9z6PtUM6tzDc62apcZkoGJwPgx48JqESgWyAz2");
 //   mariadbNEW_USER("test123", "test122", "test123@gmail.com");
 //   loginfo(generateRandomStringHoneyPI());
 //   loginfo(generateRandomStringRouterAPI());
 //   mariadbINSERT_PIKEY(generateRandomStringHoneyPI(), "test123");


    // DETERMINE TIME
    startuptime = time(NULL);
    startupchecks = startupchecks + timedetector();




    // PING MARIADB SERVER TO VERIFY CONNECTION
    startupchecks = startupchecks + mariadb_ping();




    // SET DOCKER CONTAINER OPTIONS
    loginfo("DOCKER - Setting Container Options...", false);
    signal(SIGTERM, handleSignal);
    signal(SIGINT, handleSignal);
    sendtolog("OK");
    sleep(0.5);




    // DETERMINE NETWORK CONNECTIVITY
    loginfo("NETWORK - Checking Network Connectivity...", false);
    int learnt = system("ping -c 5 8.8.8.8 > nul:");
    if (learnt == 0) {
        sendtolog("Done");
    } else {
        sendtolog("ERROR");
        logcritical("UNABLE TO DETERMINE NETWORK CONNECTIVITY!", true);
        logcritical("Killing", true);
        startupchecks = startupchecks + 1;
        return 1;
        return 1;
        return 1;
    }






    // CHECK FOR SYSTEM UPDATES
    sleep(0.5);

    loginfo("UPDATES - Checking for Server Updates...", false);
    bool serverupdate = checkserverupdateavailable();
    loginfo("UPDATES - Checking for HoneyPi Updates...", false);
    bool honeypiupdate = checkhoneypiupdateavailable();

    sleep(1);




    // VERIFY SERVER FOLDERS ARE OPEN
    loginfo("Validating COG Directory...", false);
    int testing = system("touch /home/crashlogs/test.txt");
    if (testing != 0) {
        sendtolog("ERROR");
        logcritical("UNABLE TO WRITE TO CRASHLOGS FOLDER!", true);
        startupchecks = startupchecks + 1;
    } else {
        int working = system("rm /home/crashlogs/test.txt");
        if (working != 0) {
            sendtolog("ERROR");
            logcritical("UNABLE TO CLEAR CRASHLOGS FOLDER!", true);
            startupchecks = startupchecks + 1;
        } else {
            sendtolog("DONE");
        }
    }



    // CALL NEW HTML MAIN WEB PAGES
    loginfo("HTML - Updating to Main Head...", false);
    int res256 = system(updatehtmlmainweb);
    if (res256 == 0) {
        sendtolog("DONE");
    } else {
        sendtolog("ERROR");
        logcritical("AN ERROR OCCURRED ATTEMPTING TO UPDATE WITH MAIN HEAD!", true);
    }



    // OPEN THE SERVER FILES V3
    std::string versionID;
    std::string currentversionID = "Version: " + honeyversion + "\n";
    std::string compressed;
    int migration = 0;
    int filerun = 0;
    int filerunmax = 19;
    bool completederr = false;

    // MAIN MIGRATION/CHECK SCRIPT
    while (filerunmax >= filerun && completederr != true) {
        loginfo("FILEACCESSV3 - READING " + filemessages[filerun] + "...", false);
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
            sendtolog("Done");
            if (compressed == "") {
                logwarning(filemessages[filerun] + " - No Version Found, Writing New Version...", false);
                fileinput1.close();
                std::ofstream filecreate1;
                filecreate1.open(ipliststrictfile);
                filecreate1.seekp(0);
                filecreate1 << currentversionID << '\n';
                filecreate1.flush();
                if (filecreate1.fail() == true) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO " + filemessages[filerun], true);
                    if (filecreate1.bad() == true) {
                        logcritical("AN I/O ERROR OCCURRED", true);
                    }
                    startupchecks = startupchecks + 1;
                    filecreate1.close();
                }
                sleep(0.5);
                sendtolog("Done");
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
                                        sendtolog("COMPLETED!");
                                        sleep(1);
                                    } else {
                                        sendtolog("ERROR");
                                        logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (5)!", true);
                                        sleep(2);
                                        startupchecks = startupchecks + 1;
                                    }
                                } else {
                                    sendtolog("ERROR");
                                    logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (4)!", true);
                                    sleep(2);
                                    startupchecks = startupchecks + 1;
                                }
                            } else {
                                sendtolog("ERROR");
                                logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (3)!", true);
                                sleep(2);
                                startupchecks = startupchecks + 1;
                            }
                        } else {
                            sendtolog("ERROR");
                            logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (2)!", true);
                            sleep(2);
                            startupchecks = startupchecks + 1;
                        }                    
                    } else {
                        sendtolog("ERROR");
                        logcritical("AN ERROR OCCURRED IN " + filemessages[filerun] + " MIGRATION (1)!", true);
                        sleep(2);
                        startupchecks = startupchecks + 1;
                    }
                } else {
                    sleep(0.5);
                }
            }
        } else {
            sendtolog("FILE NOT FOUND!");
            logwarning("CREATING NEW " + filemessages[filerun] + " FILE...", false);
            std::string stringcommandlocation = filelocations[filerun];
            std::string filetocreate = "touch " + stringcommandlocation;
            const char* filetocreatechar = filetocreate.c_str();
            int res260 = system(filetocreatechar);
            std::ofstream filecreate1;
            filecreate1.open(filelocations[filerun]);
            if (filecreate1.is_open() == true) {
                filecreate1 << "Version: " << honeyversion << std::endl << std::endl << std::endl;
                filecreate1.flush();
                if (filecreate1.fail() == true) {
                    sendtolog("ERROR");
                    logcritical("AN ERROR OCCURRED WRITING TO " + filemessages[filerun], true);
                    if (filecreate1.bad() == true) {
                        logcritical("AN I/O ERROR OCCURRED", true);
                    }
                    startupchecks = startupchecks + 1;
                    filecreate1.close();
                }
                filecreate1.close();
            } else {
                sendtolog("ERROR");
                logcritical("UNABLE TO CREATE NEW" + filemessages[filerun] + "FILE!", true);
                startupchecks = startupchecks + 1;
            }
        }
        filerun = filerun + 1;
    }



    // LOAD MAINHTML INTO RAM
    loginfo("HTML - Loading MAINHTML Into RAM...", true);
    int ram1 = loadHTMLINTORAM();
    if (ram1 != 0) {
        sendtolog("ERROR");
        logcritical("AN ERROR OCCURRED LOADING MAINHTML INTO RAM...", false);
        sendtolog("IGNORING!");
    } else {
        sendtolog("Done");
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
    loginfo("P80 - Opening Server Ports (1/4)", false);
    sleep(0.5);
    std::thread acceptingClientsThread80(handleConnections80);
    acceptingClientsThread80.detach();
    sendtolog("...Done");
    sleep(0.5);

    // OPEN NETWORK SERVER PORTS (2/4)
    PORT = 443;
    loginfo("P443 - Opening Server Ports (2/4)", false);
    port4 = createnetworkport443();
    sendtolog("...Done");
    sleep(0.5);

    // OPEN NETWORK SERVER PORTS (3/4)
    PORT = 11829;
    loginfo("P11829 - Opening Server Ports (3/4)", false);
    int server_fd2, new_socket2;
    ssize_t valread2;
    struct sockaddr_in address2;
    socklen_t addrlen2 = sizeof(address2);
    int opt2 = 1;
    
    sleep(0.5);

    if((server_fd2 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logcritical("P11829 - FAILED TO START SOCKET", true);
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 11829
    if (setsockopt(server_fd2, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt2, sizeof(opt2))) {
        logcritical("P11829 - FAILED TO SET SOCKET OPT", true);
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address2.sin_family = AF_INET;
    address2.sin_addr.s_addr = INADDR_ANY;
    address2.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd2, (struct sockaddr*)&address2, sizeof(address2)) < 0) {
        logcritical("P11829 - FAILED TO SET BIND", true);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd2, 3) < 0) {
        logcritical("P11829 - FAILED TO START LISTEN", true);
        exit(EXIT_FAILURE);
    }

    sendtolog("Done");
    sleep(0.5);





    // SERVER PORT LISTEN THREAD (1/4) (11829)
    loginfo("P11829 - Creating server thread on listen...", false);

    sleep(1);
    std::thread thread11829(handle11829Connections, server_fd2, 0);
    thread11829.detach();
    sleep(0.5);

    sendtolog("Done");





    // OPEN SERVER PORT 11830 FOR TELEMETRY
    loginfo("P11830 - Opening Server Ports (4/4)", false);
    PORT = 11830;
    int server_fd3, new_socket3;
    ssize_t valread3;
    struct sockaddr_in address3;
    socklen_t addrlen3 = sizeof(address3);
    int opt3 = 1;
    
    sleep(1);

    if((server_fd3 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logcritical("P11830 - FAILED TO START SOCKET OPERATION", true);
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 11535
    if (setsockopt(server_fd3, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt3, sizeof(opt3))) {
        logcritical("P11830 - FAILED TO SET SOCKET OPT", true);
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address3.sin_family = AF_INET;
    address3.sin_addr.s_addr = INADDR_ANY;
    address3.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd3, (struct sockaddr*)&address3, sizeof(address3)) < 0) {
        logcritical("P11830 - FAILED TO BIND TO PORT", true);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd3, 3) < 0) {
        logcritical("P11830 - FAILED TO START LISTEN", true);
        exit(EXIT_FAILURE);
    }

    sendtolog("Done");
    sleep(0.5);




    // SERVER PORT LISTEN THREAD (11830)
    loginfo("P11830 - Creating server thread listen...", false);

    sleep(1);
    std::thread acceptingClientsThread3(handle11830Connections, server_fd3);
    acceptingClientsThread3.detach();
    sleep(0.5);

    sendtolog("Done");




    // SERVER PORT LISTEN THREAD (443)
    loginfo("P443 - Creating server thread on listen...", false);

    sleep(1);
    std::thread acceptingClientsThread443(handleConnections443, port4);
    acceptingClientsThread443.detach();
    sleep(0.5);

    sendtolog("Done");




    // CHECK FOR THIS!
    if (serverdumpfilefound == true) {
        debugout("FUTURE THINGS!");
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

    
    return startupchecks;
}






int main() {

    // SETUP LOOP
    int startup = setup();

    if (startup != 0 && EXCEPTION != true) {
        sendtolog("ERROR");
        logcritical("STARTUP CHECKS RETURNED EXIT CODE 1", true);
        logcritical("THE SYSTEM COULD NOT CONTINUE!", true);
        logcritical("ALL DOCKER CONTAINERS WILL BE STOPPED", true);

        close(serverport1);
        close(serverport2);
        sleep(5);

        // EXIT AND STOP PROCESSES
        return(1);
        return(1);
        return(1);
    } else {



        loginfo("HoneyPi Server has started successfully", true);

        // NETWORK INFORMATION
        char buffer[BUFFER_SIZE];
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        // MAIN RUNNING LOOP
        while(startupchecks == 0 && encounterederrors == 0 && stopSIGNAL.load() == 0) {

            sleep(2);
            loginfo("Running = TRUE...", true);


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
            sendtolog("ERROR");
            logcritical("HONEYPI-SERVER HAS ENCOUNTERED UNRECOVERABLE ERRORS WHILE RUNNING!", true);
            logcritical("HONEYPI-SERVER WILL NOW ATTEMPT A LOG DUMP!", true);
            
            
            // ENCOUNTERED ERRORS LOG DUMP


            logcritical("HONEYPI-SERVER WILL NOW ATTEMPT A SAVEFILE DUMP!", true);


            // ENCOUNTERED ERRORS SAVE FILE DUMP


            logcritical("ATTEMPTING TO KILL SERVER!!!", true);
            close(serverport1);
            close(serverport2);
            return 1;
            return 1;
            return 1;
            return 1;
            return 1;
        }


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