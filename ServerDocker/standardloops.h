// STANDARD LOOP DECLARATION AND FUNCTIONS
#include <string>




#ifndef STANDARDLOOPS_H
#define STANDARDLOOPS_H

// CURRENT TIME/DATE
std::string timedetector();

// LOG OUTPUT COMMANDS
void sendtolog(std::string);
void sendtologopen(std::string);
void logdebug(std::string, bool);
void loginfo(std::string, bool);
void logwarning(std::string, bool);
void logcritical(std::string, bool);
void logerror(std::string, std::string);

// CONVERSIONS
int stringtoint(std::string);

#endif