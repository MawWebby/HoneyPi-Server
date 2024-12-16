#include "globalvariables.h"
#include "servermaintenance.h"

const char* errorlog = "/home/serverdump/errors.txt";
const char* createnewerrorlogfile = "touch /home/serverdump/errors.txt";


// ERROR MESSAGES
// SECTOR - SECTOR THAT IS AFFECTED (0-P80; 1-P443; 2-P11829; 
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
//          LOCK = LOCK MODULE FROM RUNNING (P80, P443, P11829)
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





/////////////////////////
// THE MAIN CRASH LOOP //
/////////////////////////
// HARDCRASH - PERMANENT LOCKOUT
// SECTOR - SECTOR THAT IS AFFECTED (0-P80; 1-P443; 2-P11829; 4-MARIADB; 5-MARIADBHANDLER; 6-STATUSMARIADB; 7-READ/WRITEERROR; 8-ENCRYPTION_ERROR; 9-COG_STORE_ERROR; 10-ERROR_MODULE)
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

