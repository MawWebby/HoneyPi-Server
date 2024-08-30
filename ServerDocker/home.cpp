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
#include <mariadb/conncpp.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>


const bool debug = false;
const bool testing = false;


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
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////



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
int packetspam = 0;
bool waiting230 = false;
bool api11829 = false;
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
const std::string httpfail = "HTTP/1.1 504 OK\nContent-Type:text/html\nContent-Length: 30\n\n<h1>504: Gateway Time-Out</h1>";
const std::string httpforbidden = "HTTP/1.1 403 OK\nContent-Type:text/html\nContent-Length: 23\n\n<h1>403: Forbidden</h1>";
const std::string httpservererror = "HTTP/1.1 505 OK\nContent-Type:text/html\nContent-Length: 72\n\n<h1>505: An Internal Server Error Occurred, Please Try Again Later.</h1>";
const std::string httpnotfound = "HTTP/1.1 404 OK\nContent-Type:text/html\nContent-Length: 28\n\n<h1>404: Page Not Found</h1>";




// API VARIABLES
const std::string apireject = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 17\n\n{state: rejected}";
const std::string apiincomplete = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 19\n\n{state: incomplete}";
const std::string apisendcog = "HAPI/1.1 200 OK\nContent-Type:text/json\nContent-Length: 13\n\n{state: send}";
const std::string apiwaittosend = "HAPI/1.1 222 OK\nContent-Type:text/json\nContent-Length: 13\n\n{state: wait}";
const std::string apideny = "HAPI/1.1 400 OK\nContent-Type:test/json\nContent-Length: 15\n\n{state: denied}";
const std::string apiunavailable = "HAPI/1.1 403 OK\nContent-Type:text/json\nContent-Length: 20\n\n{state: unavailable}";
const std::string apinotfound = "HAPI/1.1 404 OK\nContent-Type:text/json\n\nContent-Length: 17\n\n{state: notfound}";
const std::string apitrigger = "HAPI/1.1 200 OK\nContent-Type:text/json\n\nContent-Length:18\n\n{state: triggered}";
const std::string apisuccess = "HAPI/1.1 200 OK\nContent-Type:test/json\nContent-Length: 17\n\n{state: success}";



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
const char* bloghtmlfile = "/home/htmlmainweb/blog.html";
const char* loginhtmlfile = "/home/htmlmainweb/login.html";
const char* TOSFreefilefile = "/home/htmlmainweb/TOSFree.html";
const char* TOSProfilefile = "/home/htmlmainweb/TOSPro.html";
const char* TOSEnterprisefile = "/home/htmlmainweb/TOSEnterprise.html";
const char* PrivacyPolicyfile = "/home/htmlmainweb/privacypolicy.html";
const char* getstartedfile = "/home/htmlmainweb/get-started.html";
const char* accountfile = "/home/htmlmainweb/account.html";
const char* htmlfolder = "/home/htmlmainweb";
const char* signuphtmlfile = "/home/htmlmainweb/signup.html";
const char* configpagehtml = "/home/htmlmainweb/config.html";
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





////////////////////////////
////////////////////////////
//// MARIADB OPERATIONS ////
////////////////////////////
////////////////////////////

// MARIADB TEST
int mariadb_test() {
    
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
    
    loginfo("TRUE");
    res->next();
    std::cout << "User = " << res->getString(1);

    return 0;
}

// CHECK FOR IP ADDRESS IN serversecurity
int mariadb_CHECKIPADDR(std::string ipaddr) {
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
        return 0;
    }

    // RETURN 255 - IPADDR NOT FOUND IN DB PREVIOUSLY
    return 255;
}

// ADD IP ADDRESS IN serversecurity
int mariadb_ADDIPADDR(std::string ipaddr) {
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

// ADD BLOCKED IP ADDRESS IN serversecurity
int mariadb_BLOCKIPADDR(std::string ipaddr) {
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

// UNBLOCK IP ADDRESS IN serversecurity
int mariadb_UNBLOCKIPADDR(std::string ipaddr) {
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

// ADD PACKET TO IP ADDRESS IN serversecurity
int mariadb_ADDPACKETTOIPADDR(std::string ipaddr) {
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

// REMOVE PACKET FROM IP ADDRESS
int mariadb_REMOVEPACKETFROMIPADDR( std::string ipaddr) {



    return 0;
}

// IP ADDRESS IS DEVELOPER BLOCKED AND WON'T CONTINUE SEARCHING
bool mariadb_READDEVBLOCK(std::string ipaddr) {
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

// REMOVE OLD IP ADDR
int mariadb_REMOVEOLDIPADDR(std::string ipaddr) {
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

// CLEAR IP ADDRESSES (MAINTENANCE AND DECREASE PACKETS FOR OTHER IPs)
int mariadb_MAINTENANCE() {
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

// MARIADB LAST TIME TO PACKET
int mariadb_LASTTIMETOPACKET(std::string ipaddr) {
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

// READ THE VALUE OF PI API
std::string mariadbREAD_VALUEPIAPI(std::string user) {
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

// READ THE VALU7E OF ROUTER API
std::string mariadbREAD_VALUEROUTERAPI(std::string user, int apinumber) {
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

// READ THE VALUE OF THE EMAIL ADDRESS
int mariadbREAD_EMAILADDRESS(std::string user) {




    return 0;
}

// RESET THE PASSWORD DB ACCESS
int mariadbRESET_PASSWORD(std::string user, std::string pass) {



    return 0;
}

// RESET THE EMAIL DB ACCESS
int mariadbRESET_EMAIL(std::string user, std::string emailaddress) {


    return 0;
}

// MARIADB PI API KEY VALIDATION
bool mariadbPIAPI_keyvalid(std::string apikey) {
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
        loginfo("TRUE");
        // FIX THIS PROBLEM, NOT READING RESULT OF A CLOSED SET"?"
        return true;
    } else {
        return false;
    }
    return false;
}

// MARIADB ROUTER API KEY VALIDATION
bool mariadbROUTERAPI_keyvalid(std::string apikey) {
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
        logcritical("MATCH SEEN");
        return true;
    } else {
        return false;
    }
    return false;
}

// MARIADB NEW USER/PASSWORD/EMAIL INSERTION
int mariadbNEW_USER(std::string username, std::string password, std::string emailaddress) {
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

// MARIADB INSERT NEW HONEY PI API KEY
int mariadbINSERT_PIKEY(std::string honeypikey, std::string username) {
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

// MARIADB INSERT NEW HONEY ROUTER API 
// FIX THIS PROBLEM OF NEEDING 5 APIS FOR ONE ACCOUNT
int mariadbINSERT_ROUTERKEY(std::string routerkey, int slottoinsert, std::string username) {
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

// MARIADB VALIDATE USER CREDENTIALS
bool mariadbVALIDATE_USER(std::string username, std::string password) {
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

            std::istream *hello3 = res2->getBlob(1);
            std::string piapi1 = "";
            *hello3 >> piapi1;
            if (piapi1 == "1") {
                return true;
            } else {
                return false;
            }
        } else {
            credentialsmatch = false;
            return false;
        }
    } else {
        return false;
    }    
    return false;
}

// MARIADB INSERT NEW CLIENT SESSION KEY
int mariadbINSERT_SESSIONKEY(std::string username, std::string sessionToken) {
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

// MARIADB CHECK-IN SCRIPT
int mariadbCHECKIN_HONEYPI(std::string apikey) {




    return 0;
}

// MARIADB ROTATE CREDENTIALS/HOUR
int mariadbROTATE_CREDENTIALShour() {




    return 0;
}

// REMOVE ALL SESSION TOKENS EVERY 24 HOURS
int mariadbREMOVE_SESSIONTOKENS() {




    return 0;
}

// MARIADB ROTATE CREDENTIALS/DAY
int mariadbROTATE_CREDENTIALSday() {




    return 0;
}

// MARIADB INVALIDATE CREDENTIALS
int mariadbINVALIDATE_CREDENTIALS(std::string user, std::string pass, std::string email) {




    return 0;
}

// MARIADB PAYMENT RECEIVED
int mariadbRECEIVE_PAYMENT(std::string user, bool truereceive) {




    return 0;
}

// MARIADB SET PAYMENT PLAN
int mariadbSE_TPAYMENT(std::string user, int paymentlevel) {




    return 0;
}

// REMOVE PI API FROM DB
int mariadbREMOVE_PIAPI(std::string user) {



    return 0;
}

// REMOVE ROUTER API FROM DB
int mariadbREMOVE_ROUTERAPI(std::string user) {



    return 0;
}







/////////////////////////////////////
//// GENERATE API RANDOM STRINGS ////
/////////////////////////////////////
std::string generateRandomStringHoneyPI() {
    loginfo("CREATING NEW HoneyPi API KEY");

    // Define the list of possible characters
    const std::string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
    const std::string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
    const std::string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
    const std::string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
        std::string httpsuccess = "HTTP/1.1 200 OK\r\nContent-Type:text/html\r\nConnection: close\r\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = mainhtmlpayload.length();
        mainhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + mainhtmlpayload;
        htmlmain.close();
        return 0;
    } else {
        mainhtmlpayload = httpservererror;
        htmlmain.close();
        return 1;
    }
    mainhtmlpayload = httpservererror;
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
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                pricinghtmlpayload = pricinghtmlpayload + templine;
            }
        }
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = pricinghtmlpayload.length();
        pricinghtmlpayload = httpsuccess + std::to_string(length) + beforepayload + pricinghtmlpayload;
        htmlprice.close();
        return 0;
    } else {
        pricinghtmlpayload = httpservererror;
        htmlprice.close();
        return 1;
    }
    pricinghtmlpayload = httpservererror;
    htmlprice.close();
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = blogpayload.length();
        blogpayload = httpsuccess + std::to_string(length) + beforepayload + blogpayload;
        bloghtml.close();
        return 0;
    } else {
        blogpayload = httpservererror;
        bloghtml.close();
        return 1;
    }
    blogpayload = httpservererror;
    bloghtml.close();
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
        std::string httpsuccess = "HTTP/1.1 200 OK\r\nContent-Type:text/html\r\nConnection: close\r\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = loginpayload.length();
        loginpayload = httpsuccess + std::to_string(length) + beforepayload + loginpayload;
        loginhtml.close();
        return 0;
    } else {
        loginpayload = httpservererror;
        loginhtml.close();
        return 1;
    }
    loginpayload = httpservererror;
    loginhtml.close();
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
        std::string httpsuccess = "HTTP/1.1 200 OK\r\nContent-Type:text/html\r\nConnection: close\r\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = signuppayload.length();
        signuppayload = httpsuccess + std::to_string(length) + beforepayload + signuppayload;
        signuphtml.close();
        return 0;
    } else {
        loginpayload = httpservererror;
        signuphtml.close();
        return 1;
    }
    loginpayload = httpservererror;
    signuphtml.close();
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
        std::string beforepayload = "\n\n";
        int length = getstartedpayload.length();
        getstartedpayload = httpsuccess + std::to_string(length) + beforepayload + getstartedpayload;
        getstartedstream.close();
        return 0;
    } else {
        getstartedpayload = httpservererror;
        getstartedstream.close();
        return 1;
    }
    getstartedpayload = httpservererror;
    getstartedstream.close();
    return 1;
}

int loadHTMLINTORAM() {
    loginfo("Loading All Main HTML Pages into RAM!");
    int returnvalue = 0;
    returnvalue = returnvalue + loadmainHTMLintoram();
    loginfo("Done with index.html");
    returnvalue = returnvalue + loadpricingHTMLintoram();
    loginfo("Done with pricing.html");
    returnvalue = returnvalue + loadblogHTMLintoram();
    loginfo("Done with blog.html");
    returnvalue = returnvalue + loadloginHTMLintoram();
    loginfo("Done with login.html");
    returnvalue = returnvalue + loadsignupHTMLintoram();
    loginfo("Done with signup.html");
    returnvalue = returnvalue + loadgetstartedHTMLintoram();
    loginfo("Done with getstarted.html");
    // returnvalue = returnvalue + 
    loginfo("Done Loading into Ram");
    return returnvalue;
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
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
        std::string httpsuccess = "HTTP/1.1 200 OK\nContent-Type:text/html\nContent-Length: ";
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
    loginfo("HTTP THREAD");
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

    loginfo("True through ssl checks");

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        logwarning("SSL_ACCEPT NOT TRUE!");
    } else {
        loginfo("TURe");
        // Buffer to read the incoming request
        char buffer[2048] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        int timer89 = 0;
        logwarning(buffer);
        int timer89max = 5;
        bool completed23 = false;
        if (buffer != "" && sizeof(buffer) >= 7) {
            std::string bufferstring = buffer;
            std::string headerrequest = bufferstring.substr(0,4);
            
            if (bufferstring.length() >= 7) {
                // CHANGE HERE FROM GET: / TO GET /
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
                                if (microstring != "H" && microstring != "/" && microstring != " ") {
                                    if (dashesreceived > 1) {
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

                            // LOGINTOACCOUNT
                            if (headerstringpost == "logintoaccount") {
                                loginfo("logintoaccount received");
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
                                    loginfo(jsonlogin);

                                    // GO AHEAD TO ANALYZE JSON AND SEND IT TO MARIADB TO VERIFY
                                    std::string userstringverify = jsonlogin.substr(2,8);
                                    logwarning(userstringverify);
                                    if (userstringverify == "username"){
                                        std::string verifyjson = jsonlogin.substr(11,1);
                                        int analyzenumber = 12;
                                        logcritical(verifyjson);
                                        if (verifyjson == ":") {
                                            int timering80 = 0;
                                            int timering80max = 80;
                                            bool timering80set = false;
                                            int quotations = 0;
                                            int characternumber = 0;
                                            std::string hellostring = "";
                                            std::string username = "";
                                            while (timering80 <= timering80max && timering80set != true && quotations < 2) {
                                                logwarning(hellostring);
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
                                            logcritical(hellostring);

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
                                                    logwarning(hellostring);
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
                                                if (verified == true) {
                                                    // CREATE SESSION TOKEN AND REDIRECT
                                                    std::string sessiontoken = generateRandomClientKey();
                                                    mariadbINSERT_SESSIONKEY(username, sessiontoken);
                                                    sleep(1);
                                                    int contentlength = 0;
                                                    char doublequote = '"';
                                                    // SEND MODIFIED JSON WITH SUCCESS, CLIENT TOKEN, AND ADDRESS TO FORWARD TO...
                                                    std::string sendpayloadforlength = "{" + doublequote + std::string("state") + doublequote + ":" + doublequote + "ok" + doublequote + "," + doublequote + "token" + doublequote + ":" + doublequote + sessiontoken + doublequote + "," + doublequote + "redirect" + doublequote + ":" + doublequote + "account.html" + doublequote + "}";
                                                    contentlength = sendpayloadforlength.length();
                                                    std::string sendpayloadtoclient = "HTTP/1.1 200 OK\r\nContent-Type:application/json\r\nContent-Length: " + std::to_string(contentlength) + "\r\nConnection: close\r\n" + sendpayloadforlength;
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
    
    //sleep(600);
    //mariadb_REMOVEPACKETFROMIPADDR(ipaddr);
} 

void handleConnections443(int server_fd) {

    port80runningstatus = true;
    int threadnumber = 0;    

    static bool initialized = false;
    port80runningstatus = true;
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
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return;
    }
    loginfo("Started!");



    while (port80runningstatus == true) {
        

        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("Unable to accept");
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        } else {
            ssl = SSL_new(ctx);
            if (!ssl) {
                ERR_print_errors_fp(stderr);
                close(client_fd);
                SSL_CTX_free(ctx);
                return;
            }
            SSL_set_fd(ssl, client_fd);

            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "Connection from: " << client_ip << '\n';
            std::string clientipstd = client_ip;

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
                    threadnumber = threadnumber + 1;
                    if (threadnumber >= 10000) {
                        threadnumber = 0;
                    }
                    std::string threadname = "https" + std::to_string(threadnumber);
                    std::thread threadnametrigger(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                // setThreadName(threadname);
                    threadnametrigger.detach();
                }
            }
        }   
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    logcritical("Finished!");
}


////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (80) - MAIN HTTP SERVER!! //
////////////////////////////////////////////////////////////
void handleHTTPRedirect(int server_fd) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    int client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (client_fd < 0) {
        perror("Unable to accept");
        return;
    }

    // Simple HTTP response for redirection
    const char *response =
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: https://10.72.91.159/ \r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";

    // Send the redirect response
    send(client_fd, response, strlen(response), 0);

    // Close the connection
    close(client_fd);
}

void handleConnections80() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(80);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 10);

    while (true) {
        handleHTTPRedirect(server_fd);
    }

    close(server_fd);
}





////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (11829) - MAIN API SERVER //
////////////////////////////////////////////////////////////
void handle11829Connections(int server_fd2) {
    api11829 = true;
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
        

        if ((new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
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
                if ((new_socket2 = accept(server_fd2, (struct sockaddr*)&address, &addrlen)) < 0) {
                    perror("accept");
                    exit(EXIT_FAILURE);
                } else {
                    loginfo("11829 port initialized");
                }
            
                read(new_socket2, buffer, 2048);
                sendtologopen(buffer);
                std::string bufferstd = buffer;

                if (bufferstd.length() >= 8) {
                    // READ BUFFER LENGTH HERE
                    
                    // MAKE SURE THAT IT IS A VALID STRING
                    std::string buffertests = bufferstd.substr(0,1);
                    std::string realstring;

                    if (buffertests == "{") {
                        // START READING STATEMENTS
                        buffertests = bufferstd.substr(1,5);
                        bool shiftfound = false;

                        // CORRESPONDING TO ABCDE; ADD TEN CASES !SHIFTS!
                        if (buffertests == "ABCDE") {
                            // SHIFT 0
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "BCDEF") {
                            // SHIFT +1
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "CDEFG") {
                            // SHIFT +2
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "DEFGH") {
                            // SHIFT +3
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "EFGHI") {
                            // SHIFT +4
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "FGHIJ") {
                            // SHIFT +5
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "zABCD") {
                            // SHIFT -1
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "yzABC") {
                            // SHIFT -2
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "xyzAB") {
                            // SHIFT -3
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "wxyzA") {
                            // SHIFT -4
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }
                        if (buffertests == "vwxyz") {
                            // SHIFT -5
                            shiftfound = true;
                            realstring = bufferstd.substr(6, bufferstd.length() - 6);
                        }





                        // SHIFT HAS BEEN FOUND, START ANALYZING THE ACTUAL STRING
                        if (shiftfound == true && realstring != "") {
                            // CONTINUE ANALYZING
                            if (realstring.length() >= 7) {
                                // PING VERSION 0.1
                                if (realstring.substr(0,6) == "status") {
                                    // PING FOR HONEYPI THINGS
                                }
                                
                                // REPORT NEW COG
                                if (realstring.substr(0,6) == "report") {
                                    if (cogswaiting >= 20) {
                                        while (cogswaiting >= 20) {
                                            sleep(3);
                                            int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                                        }
                                    }
                                    int send_res=send(new_socket2,apisendcog.c_str(),apisendcog.length(),0);
                                }

                                // CREATE NEW SERVER ACCOUNT
                                if (realstring.substr(0.6) == "create") {

                                }

                                // RESET PASSWORD
                                if (realstring.substr(0,6) == "passwo") {
                                    
                                }

                                // LOAD/CREATE API KEY
                                if (realstring.substr(0.6) == "apikey") {
                                    if (realstring.length() >= 12) {
                                        if (realstring.substr(6,1) == ",") {
                                            if (realstring.substr(7,5) == "show:") {
                                                if (realstring.length() >= 15) {
                                                    if (realstring.substr(12,3) == "pi}") {
                                                        // SHOW THE HONEYPI API FOR PI

                                                    }

                                                    if (realstring.substr(12,3) == "rou") {
                                                        // SHOW THE HONEYPI API FOR PI

                                                    }
                                                } else {
                                                    // SEND ERROR ON API PORT
                                                    int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                                                }
                                            }
                                            
                                            if (realstring == "creat") {
                                                // CREATE NEW HONEYPI API TOKENS
                                            }
                                        } else {
                                            // SEND ERROR ON API PORT
                                            int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                                        }
                                    } else {
                                        // SEND ERROR ON API PORT
                                        int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                                    }
                                }
                            } else {
                                if (realstring.length() >= 4) {

                                    // PING FOR HONEYPI NEW
                                    if (realstring.substr(0,4) == "ping") {
                                        // NEW PING FOR HONEYPI
                                    }
                                } else {
                                    // SEND ERROR ON API PORT
                                    int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                                }
                            }
                        } else {
                            // SEND ERROR ON API PORT
                            int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                        }
                    } else {
                        // SEND ERROR ON API PORT
                        int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
                    }
                } else {
                    // SEND ERROR ON API PORT
                    int send_res=send(new_socket2,apireject.c_str(),apireject.length(),0);
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
void handle11830Connections(int server_fd2) {
    api11829 = true;
    while(api11829 == true) {
        char buffer[2048] = {0};
        struct sockaddr_in address;
        socklen_t addrlen = sizeof(address);
        int new_socket2;
        ssize_t valread;
        std::string hello = "Hello from server";
    //   socklen_t client_addr_len = sizeof(client_addr);

        if ((new_socket2 = accept(server_fd2, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        } else {
            loginfo("11829 port initialized");
        }

    
 //       std::fill_n(buffer, 2048, "");
//        char client_ip[INET_ADDRSTRLEN];
 //       inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        read(new_socket2, buffer, 2048);
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
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 80
    if (setsockopt(server_fd3, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address3.sin_family = AF_INET;
    address3.sin_addr.s_addr = INADDR_ANY;
    address3.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd3, (struct sockaddr*)&address3, sizeof(address3)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd3, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_fd3;
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
    // DEPRECATED DUE TO USING MARIADB TO STORE THIS INFORMATION INSTEAD! (8/18/24)

    /*
    sendtologopen("[INFO] - Loading IPSAFETY Into RAM...");
    int ram = loadipsafetyintoram();
    if (ram != 0) {
        sendtolog("ERROR");
        logcritical("AN ERROR OCCURRED LOADING IPSAFETY INTO RAM!");
        startupchecks = startupchecks + 1;
    } else {
        sendtolog("Done");
    }
    */



    // LOAD MAINHTML INTO RAM
    sendtologopen("[INFO] - Loading MAINHTML Into RAM...");
    int ram1 = loadHTMLINTORAM();
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
    sendtologopen("[INFO] - Opening Server Ports (1/4)");
    port1 = createnetworkport80();
    sendtolog("Done");
    sleep(3);

    PORT = 80;
    sendtologopen("[INFO] - Opening Server Ports (2/4)");
    port4 = createnetworkport443();
    sendtolog("Done");
    sleep(3);

    // OPEN NETWORK SERVER PORTS (2/3)
    PORT = 11829;
    sendtologopen("[INFO] - Opening Server Ports (3/4)...");
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





    // SERVER PORT LISTEN THREAD (2/3) (11829)
    sendtologopen("[INFO] - Creating server thread on port 11829 listen...");

    sleep(2);
    std::thread acceptingClientsThread2(handle11829Connections, server_fd2);
    acceptingClientsThread2.detach();
    sleep(1);

    sendtolog("Done");





    // OPEN SERVER PORT 11830 FOR TELEMETRY
    sendtologopen("[INFO] - Opening Server Ports (4/4)...");
    PORT = 11830;
    int server_fd3, new_socket3;
    ssize_t valread3;
    struct sockaddr_in address3;
    socklen_t addrlen3 = sizeof(address3);
    int opt3 = 1;
    
    sleep(1);

    if((server_fd3 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 11535
    if (setsockopt(server_fd3, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt3, sizeof(opt3))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // REACHED HERE
    sendtologopen("...");
    address3.sin_family = AF_INET;
    address3.sin_addr.s_addr = INADDR_ANY;
    address3.sin_port = htons(PORT);

    // Binding the socket to the network address and port
    if (bind(server_fd3, (struct sockaddr*)&address3, sizeof(address3)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd3, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    sendtolog("Done");
    sleep(2);




    // SERVER PORT LISTEN THREAD (3/3) (118.30)
    sendtologopen("[INFO] - Creating server thread on port 11830 listen...");

    sleep(2);
    std::thread acceptingClientsThread3(handle11830Connections, server_fd3);
    acceptingClientsThread3.detach();
    sleep(1);

    sendtolog("Done");





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
        sendtologopen("[INFO] - Creating server thread on port 443 listen...");

        sleep(2);
        std::thread acceptingClientsThread443(handleConnections443, port4);
        acceptingClientsThread443.detach();
        sleep(1);

        sendtolog("Done");


        // SERVER PORT LISTEN THREAD
        sendtologopen("[INFO] - Creating server thread on port 80 listen...");

        sleep(2);
        std::thread acceptingClientsThread80(handleConnections80);
        acceptingClientsThread80.detach();
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