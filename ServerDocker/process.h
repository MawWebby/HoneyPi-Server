// PROCESS THE COMMANDS AND RECEIVE THE OUTPUT
#include <string>

#ifndef PROCESS_H
#define PROCESS_H

// UNENCRYPT COG
std::string unencryptcog(std::string, std::string);

// MAIN PROCESS LOOP
int processReport(std::string, std::string);

// CACHE INTO AL DBs
int cacheseverity();


#endif