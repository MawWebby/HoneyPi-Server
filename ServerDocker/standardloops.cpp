#include "standardloops.h"
#include "globalvariables.h"


std::string charactermap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
int serverStatus;
int updating;
int stopping;

// LOGFILE
const char* logfile = "/home/serverdump/log.txt";
const char* packetfile = "/home/serverdump/packetlog.txt";


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
    serverStatus = serverStarted.load();
    updating = updateSIGNAL.load();
    stopping = stopSIGNAL.load();

    if (serverStatus == false || updating == true || stopping == true) {
        std::cout << data2 << std::endl;
    } 
    
    std::ofstream logfilestream;
    logfilestream.open(logfile, std::ofstream::out | std::ofstream::app);
    if (logfilestream.is_open() == true) {
        logfilestream << data2 << std::endl;
    } else {
        std::cout << "[ERRO] - COULD NOT SAVE TO LOGFILE!" << std::endl;
        std::cout << "[ERRO] - MESSAGE: " << data2 << std::endl;
    }
    logfilestream.close();
}

void sendtologopen(std::string data2) {
    serverStatus = serverStarted.load();
    updating = updateSIGNAL.load();
    stopping = stopSIGNAL.load(); 

    if (serverStatus == false || updating == true || stopping == true) {
        std::cout << data2;
    } 
    
    std::ofstream logfilestream;
    logfilestream.open(logfile, std::ofstream::out | std::ofstream::app);
    if (logfilestream.is_open() == true) {
        logfilestream << data2;
    } else {
        std::cout << "[ERRO] - COULD NOT SAVE TO LOGFILE!" << std::endl;
        std::cout << "[ERRO] - MESSAGE: " << data2 << std::endl;
    }
    logfilestream.close();
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




/////////////////////////////////
//// READ FROM LOGGER SRIPTS ////
/////////////////////////////////
void readfromlogger() {
    std::ifstream logfilestream;
    logfilestream.open(logfile);
    if (logfilestream.is_open() == true) {
        char linebits[2048];
        while (logfilestream.eof() == false) {
            logfilestream.getline(linebits, 2048);
            std::cout << linebits << std::endl;
        }
        std::cout << std::endl << "Reached End of Log File" << std::endl;
    } else {
        std::cout << "[ERRO] - COULD NOT OPEN LOGFILE!" << std::endl;
    }
    logfilestream.close();
}




///////////////////////////////////
// Send to PACKET Logger Scripts //
///////////////////////////////////
void packetlogger(std::string packetdata) {
    std::ofstream logfilestream;
    logfilestream.open(packetfile, std::ofstream::out | std::ofstream::app);
    if (logfilestream.is_open() == true) {
        logfilestream << packetdata << std::endl;
    } else {
        std::cout << "[ERRO] - COULD NOT SAVE TO PACKETFILE!" << std::endl;
        std::cout << "[ERRO] - MESSAGE: " << packetdata << std::endl;
    }
    logfilestream.close();
}




/////////////////////////////////
//// READ FROM LOGGER SRIPTS ////
/////////////////////////////////
void readfrompacketlogger() {
    std::ifstream logfilestream;
    logfilestream.open(packetfile);
    if (logfilestream.is_open() == true) {
        char linebits[2048];
        while (logfilestream.eof() == false) {
            logfilestream.getline(linebits, 2048);
            std::cout << linebits << std::endl;
        }
        std::cout << std::endl << "Reached End of Log File" << std::endl;
    } else {
        std::cout << "[ERRO] - COULD NOT OPEN PACKETFILE!" << std::endl;
    }
    logfilestream.close();
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



//////////////////////////////////
//// INT TO STRING CONVERSION //// 
//////////////////////////////////
std::string inttostring(int value) {
    std::string returnvalue = "";
    bool single = false;
    bool doublenum = false;
    bool triple = false;
    bool quad = false;
    bool penta = false;
    bool hexa = false;

    // DETERMINE CASE
    if (value < 9) {
        single = true;
        doublenum = false;
        triple = false;
        quad = false;
        penta = false;
        hexa = false;
    } else if (value < 99) {
        single = true;
        doublenum = true;
        triple = false;
        quad = false;
        penta = false;
        hexa = false;
    } else if (value < 999) {
        single = true;
        doublenum = true;
        triple = true;
        quad = false;
        penta = false;
        hexa = false;
    } else if (value < 9999) {
        single = true;
        doublenum = true;
        triple = true;
        quad = true;
        penta = false;
        hexa = false;
    } else if (value < 99999) {
        single = true;
        doublenum = true;
        triple = true;
        quad = true;
        penta = true;
        hexa = false;
    } else if (value < 999999) {
        single = true;
        doublenum = true;
        triple = true;
        quad = true;
        penta = true;
        hexa = true;
    }

    // START WORK ON EACH CASE
    if (single == true) {
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0";
                break;
            case 1:
                returnvalue = "1";
                break;
            case 2:
                returnvalue = "2";
                break;
            case 3:
                returnvalue = "3";
                break;
            case 4:
                returnvalue = "4";
                break;
            case 5:
                returnvalue = "5";
                break;
            case 6:
                returnvalue = "6";
                break;
            case 7:
                returnvalue = "7";
                break;
            case 8:
                returnvalue = "8";
                break;
            case 9:
                returnvalue = "9";
                break;
        }
    }
    if (doublenum == true) {
        value = value / 10;
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0" + returnvalue;
                break;
            case 1:
                returnvalue = "1" + returnvalue;
                break;
            case 2:
                returnvalue = "2" + returnvalue;
                break;
            case 3:
                returnvalue = "3" + returnvalue;
                break;
            case 4:
                returnvalue = "4" + returnvalue;
                break;
            case 5:
                returnvalue = "5" + returnvalue;
                break;
            case 6:
                returnvalue = "6" + returnvalue;
                break;
            case 7:
                returnvalue = "7" + returnvalue;
                break;
            case 8:
                returnvalue = "8" + returnvalue;
                break;
            case 9:
                returnvalue = "9" + returnvalue;
                break;
        }
    }
    if (triple == true) {
        value = value / 10;
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0" + returnvalue;
                break;
            case 1:
                returnvalue = "1" + returnvalue;
                break;
            case 2:
                returnvalue = "2" + returnvalue;
                break;
            case 3:
                returnvalue = "3" + returnvalue;
                break;
            case 4:
                returnvalue = "4" + returnvalue;
                break;
            case 5:
                returnvalue = "5" + returnvalue;
                break;
            case 6:
                returnvalue = "6" + returnvalue;
                break;
            case 7:
                returnvalue = "7" + returnvalue;
                break;
            case 8:
                returnvalue = "8" + returnvalue;
                break;
            case 9:
                returnvalue = "9" + returnvalue;
                break;
        }
    }
    if (quad == true) {
        value = value / 10;
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0" + returnvalue;
                break;
            case 1:
                returnvalue = "1" + returnvalue;
                break;
            case 2:
                returnvalue = "2" + returnvalue;
                break;
            case 3:
                returnvalue = "3" + returnvalue;
                break;
            case 4:
                returnvalue = "4" + returnvalue;
                break;
            case 5:
                returnvalue = "5" + returnvalue;
                break;
            case 6:
                returnvalue = "6" + returnvalue;
                break;
            case 7:
                returnvalue = "7" + returnvalue;
                break;
            case 8:
                returnvalue = "8" + returnvalue;
                break;
            case 9:
                returnvalue = "9" + returnvalue;
                break;
        }
    }
    if (penta == true) {
        value = value / 10;
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0" + returnvalue;
                break;
            case 1:
                returnvalue = "1" + returnvalue;
                break;
            case 2:
                returnvalue = "2" + returnvalue;
                break;
            case 3:
                returnvalue = "3" + returnvalue;
                break;
            case 4:
                returnvalue = "4" + returnvalue;
                break;
            case 5:
                returnvalue = "5" + returnvalue;
                break;
            case 6:
                returnvalue = "6" + returnvalue;
                break;
            case 7:
                returnvalue = "7" + returnvalue;
                break;
            case 8:
                returnvalue = "8" + returnvalue;
                break;
            case 9:
                returnvalue = "9" + returnvalue;
                break;
        }
    }
    if (hexa == true) {
        value = value / 10;
        int numbertech = value % 10;
        switch (numbertech) {
            case 0:
                returnvalue = "0" + returnvalue;
                break;
            case 1:
                returnvalue = "1" + returnvalue;
                break;
            case 2:
                returnvalue = "2" + returnvalue;
                break;
            case 3:
                returnvalue = "3" + returnvalue;
                break;
            case 4:
                returnvalue = "4" + returnvalue;
                break;
            case 5:
                returnvalue = "5" + returnvalue;
                break;
            case 6:
                returnvalue = "6" + returnvalue;
                break;
            case 7:
                returnvalue = "7" + returnvalue;
                break;
            case 8:
                returnvalue = "8" + returnvalue;
                break;
            case 9:
                returnvalue = "9" + returnvalue;
                break;
        }
    }
    return returnvalue;
}



/////////////////////////////////////
//// GENERATE API RANDOM STRINGS ////
/////////////////////////////////////
std::string generateRandomStringHoneyPI() {

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
