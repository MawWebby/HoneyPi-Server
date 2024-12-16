#include "standardloops.h"
#include "globalvariables.h"




//////////////////////
//// TIMER SCRIPT ////
//////////////////////
std::string timedetector() {
    time_t time10 = time(0); 
    std::string dateandtime = ctime(&time10);
    std::string datestd = dateandtime.substr(0,10);
    std::string clockstd = dateandtime.substr(10, 9);
    std::string yearstd = dateandtime.substr(20,4);
    std::string newformat = datestd + ", " + yearstd + " " + clockstd;
    return newformat;
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
    std::string timedet = timedetector();
    data2 = "[DEBUG] - " + timedet + " - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void loginfo(std::string data2, bool complete) {
    std::string timedet = timedetector();
    data2 = "[INFO ] - " + timedet + " - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logwarning(std::string data2, bool complete) {
    std::string timedet = timedetector();
    data2 = "[WARN*] - " + timedet + " - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logcritical(std::string data2, bool complete) {
    std::string timedet = timedetector();
    data2 = "[ERRNO] - " + timedet + " - " + data2;
    if (complete == false) {
        sendtologopen(data2);
    } else {
        sendtolog(data2);
    }
}

void logerror(std::string headerdata2, std::string errormessage) {
    std::string timedet = timedetector();
    std::string data2 = "[ERROR] - " + timedet + " - " + headerdata2 + " - " + errormessage;
    sendtolog(data2);
}



//////////////////////////////////
//// STRING TO INT CONVERSION //// 
//////////////////////////////////
int stringtoint(std::string values) {
    long int valuesdetermine = 0;
    bool completedwhile = false;
    int timing9760 = 0;
    int timing9760max = values.length();
    bool validcase = false;
    bool periodcheck = false;
    
    // CHECK FOR NULL
    if (values.length() == 0) {
        loginfo("RECEIVED NULL STRING TO ANALYZE! (STD->INT)", true);
        return 0;
    }

    // CHECK FOR LONG INT
    if (values.length() > 9) {
        loginfo("RECEIVED A SUPER LONG STRING TO ANALYZE! (STD->INT)", true);
        return 0;
    }

    // MAIN CHECK LOOP
    std::string substringvalue = "";
    while (completedwhile == false && timing9760 <= timing9760max) {
        if (timing9760 + 1 <= timing9760max) {
            validcase = false;
            if (periodcheck == false) {
                valuesdetermine = valuesdetermine * 10;
                periodcheck = false;
            } else {
                periodcheck = false;;
            }
            substringvalue = values.substr(timing9760, 1);
            if (substringvalue == "0") {
                validcase = true;
            } else if (substringvalue == "1") {
                validcase = true;
                valuesdetermine = valuesdetermine + 1;
            } else if (substringvalue == "2") {
                validcase = true;
                valuesdetermine = valuesdetermine + 2;
            } else if (substringvalue == "3") {
                validcase = true;
                valuesdetermine = valuesdetermine + 3;
            } else if (substringvalue == "4") {
                validcase = true;
                valuesdetermine = valuesdetermine + 4;
            } else if (substringvalue == "5") {
                validcase = true;
                valuesdetermine = valuesdetermine + 5;
            } else if (substringvalue == "6") {
                validcase = true;
                valuesdetermine = valuesdetermine + 6;
            } else if (substringvalue == "7") {
                validcase = true;
                valuesdetermine = valuesdetermine + 7;
            } else if (substringvalue == "8") {
                validcase = true;
                valuesdetermine = valuesdetermine + 8;
            } else if (substringvalue == "9") {
                validcase = true;
                valuesdetermine = valuesdetermine + 9;
            }


            // DECIMALS (IGNORE THIS CASE)
            // FIX THIS
            else if (substringvalue == ".") {
                validcase = true;
                periodcheck = true;
            }


            // INVALID STRING
            if (validcase != true) {
                loginfo("AN INVALID CHARACTER WAS RECEIVED (STD->INT); THE CHARACTER WAS: ", false);
                sendtolog(substringvalue);
                completedwhile = true;
                return 0;
            }   
        } else {
            completedwhile == true;
        }
        timing9760 = timing9760 + 1;
    }

    return valuesdetermine;
}