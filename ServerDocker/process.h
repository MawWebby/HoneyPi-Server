// PROCESS THE COMMANDS AND RECEIVE THE OUTPUT
#include <string>
#include <map>

#ifndef PROCESS_H
#define PROCESS_H



// SAVE THE VARIOUS FUNCTIONS TO FILES
int saveusernamestofile(std::map<int, std::string>, bool);
int savepasswordstofile(std::map<int, std::string>, bool);
int savecommandstofile(std::map<int, std::string>, bool);
int savefoldertofile(std::map<int, std::string>, bool);
int savefilesviewedtofile(std::map<int, std::string>, bool);
int savefileeffectstofile(std::map<int, std::string>, bool);
int saveipaddrPREMIUMFILE(std::map<int, std::string>, int, bool);
int saveiptoSTANDARDFILE(std::string, bool);
int saveiptoSTRICTFILE(std::string, bool);
std::map<int, float> saveiptoTIMEBASEDFILE(std::string, int, bool);
int saveiptoMOREINFOFILE(std::string ipaddr, bool systemcall);
int saveextraopttofile(std::map<int, std::string>, bool);
int devblockipaddrtofiles(std::map<int, std::string>, bool);


// REMOVE NUMBER IF NEEDED FROM FILE
int removeusernamefromfile(std::string, bool);
int removepasswordfromfile(std::string, bool);
int removecommandfromfile(std::string, bool);



// UNENCRYPT COG
std::string unencryptcog(std::string, std::string);



// MAIN PROCESS LOOP
int processReport(std::string, std::string);



// CACHE INTO ALL DBs
// 0 => Command Severity
// 1 => Folders Viewed
// 2 => Files Changes
// 3 => Files Viewed
std::map<int, std::map<std::string, float>> cacheseverity();


#endif