// STANDARD LOOP DECLARATION AND FUNCTIONS
#include <string>


extern int currentminute;
extern int currenthour;
extern int currentdays;
extern int currentyear;


#ifndef STANDARDLOOPS_H
#define STANDARDLOOPS_H

// CURRENT TIME/DATE
std::string timedetector();

// LOG OUTPUT COMMANDS
void sendtolog(std::string, bool);
void sendtologopen(std::string, bool);
void logdebug(std::string, bool);
void logconsole(std::string, bool);
void loginfo(std::string, bool);
void logwarning(std::string, bool);
void logcritical(std::string, bool);
void logerror(std::string, std::string);

// LOG INPUT COMMANDS
void readfromlogger();

// PACKET LOG OUTPUT FUNCTIONS
void packetlogger(std::string);

// PACKET LOG INPUT FUNCTIONS
void readfrompacketlogger();

// CONVERSIONS
int stringtoint(std::string);
std::string inttostring(int);

// GENERATORS
std::string generateRandomStringHoneyPI();
std::string generateRandomStringRouterAPI();
std::string generateRandomFileName();
std::string generateRandomClientKey();

// REMOVE PACKETS
int remove11829packet(std::string);

// REMOVE PERIODS AND IPADDRS
std::string ipstring(std::string);


#endif


// FIXTHIS
// ADD CURRENT TIME HOUR/DAY/ETC.