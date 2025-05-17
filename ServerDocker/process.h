// PROCESS THE COMMANDS AND RECEIVE THE OUTPUT
#include <string>
#include <map>

#ifndef PROCESS_H
#define PROCESS_H

// SAVE THE VARIOUS FUNCTIONS TO FILES
int saveusernamestofile(std::map<int, std::string>, bool);
int savepasswordstofile(std::map<int, std::string>, bool);
int savecommandstofile(std::map<int, std::string>, bool);

// REMOVE NUMBER IF NEEDED FROM FILE
int removeusernamefromfile(std::string, bool);
int removepasswordfromfile(std::string, bool);
int removecommandfromfile(std::string, bool);

// UNENCRYPT COG
std::string unencryptcog(std::string, std::string);

// MAIN PROCESS LOOP
int processReport(std::string, std::string);

// CACHE INTO AL DBs
int cacheseverity();


#endif