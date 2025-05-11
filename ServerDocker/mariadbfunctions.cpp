#include "mariadbfunctions.h"
#include "servermaintenance.h"
#include "globalvariables.h"

////////////////////////////
//////////////////////////// 
//// MARIADB OPERATIONS ////
////////////////////////////
////////////////////////////

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
const std::string mariadbblockipaddrheader = "UPDATE serversecurity SET blockedip = '1' WHERE ipaddr = '";
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
const char* legendstring = "MyChiefDog79";


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
            sendtolog("OK", false);
            return 0;
        } else {
            logcritical("ERROR", true);
            return 1;
        }
        //std::cout << "User = " << res->getString(1);
    } 

    // CATCH EXCEPTIONS
    catch(sql::SQLException& e){
        logcritical("ERROR (CAUGHT IN EXCEPTION)", true);
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
        stmnt->executeQuery(executequery34);
        
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
        stmnt->executeQuery(executequery36);
        
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
        stmnt->executeQuery(executequery36);

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
            stmnt->executeQuery(executequery36);
            
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
            stmnt->executeQuery(executequery36);
            
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
        stmnt->executeQuery(executequery36);

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
                    mariadb_REMOVEOLDIPADDR(ipaddr);
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
            stmnt->executeQuery(executequery36);

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
        stmnt->executeQuery(executequery32);


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
        stmnt->executeQuery(executequery34);

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
        stmnt->executeQuery(executequery34);

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
        stmnt->executeQuery(executequery34);

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
        stmnt->executeQuery(executequery34);

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
            stmnt->executeQuery(executequery36);
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
        stmnt->executeQuery(executequery36);

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
// 0 - 80; 1 - 443; 2 - 11829
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

