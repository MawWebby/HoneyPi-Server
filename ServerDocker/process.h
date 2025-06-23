// PROCESS THE COMMANDS AND RECEIVE THE OUTPUT
#include <string>
#include <map>

#ifndef PROCESS_H
#define PROCESS_H



// SAVE THE VARIOUS FUNCTIONS TO FILES
int saveusernamestofile(std::map<int, std::string>, bool);//G111
int savepasswordstofile(std::map<int, std::string>, bool);//G111
int savecommandstofile(std::map<int, std::string>, bool);//G
int savefoldertofile(std::map<int, std::string>, bool);//G
int savefilesviewedtofile(std::map<int, std::string>, bool);//G
int savefileeffectstofile(std::map<int, std::string>, bool);//G
int saveipaddrPREMIUMFILE(std::map<int, std::string>, std::map<int, std::map<std::string, float>>, bool);
int saveiptoSTANDARDFILE(std::string, bool);
int saveiptoSTRICTFILE(std::string, bool);
std::map<int, float> saveiptoTIMEBASEDFILE(std::string, float, bool, int);//G111
int saveiptoMOREINFOFILE(std::string ipaddr, bool systemcall);
int saveextraopttofile(std::map<int, std::string>, bool);
int devblockipaddrtofiles(std::string, bool);



// REMOVE NUMBER IF NEEDED FROM FILE
int removeusernamefromfile(std::string, bool);//G
int removepasswordfromfile(std::string, bool);//G
int removecommandfromfile(std::string, bool);//G
int removefolderfromfile(std::string, bool);//G
int removefileviewfromfile(std::string, bool);//G
int removefileeffectfromfile(std::string, bool);//G
int removeipSTANDARDfromfile(std::string, std::string, std::string, bool);
int removeipSTRICTfromfile(std::string, std::string, std::string, bool);
int removepacketfromipaddrrawfile(std::string, std::string, std::string, bool);



// READ FROM FILES
std::map<int, std::string> readfromipraw(std::string);
std::map<int, std::map<int, std::string>> readcogprocessinglocations();
std::map<int, std::string> readlistofcogsforIP(std::string);
std::string readfromtoconsole(std::string);
int changecogfiletofinish(std::string);


// READ FROM IP FILES
int ipinstandardfile(std::string);
int ipinstrictfile(std::string);


// MAINTENANCE SCRIPTS
std::map<int, std::map<int, std::string>> runipstandardstrictpurginglist(bool, bool, bool);



// UNENCRYPT COG
std::string unencryptcog(std::string, std::string);



// MAIN PROCESS LOOP
int processReport(std::string, std::string, bool, std::string);



// CACHE INTO ALL DBs
// 0 => Command Severity
// 1 => Folders Viewed
// 2 => Files Changes
// 3 => Files Viewed
std::map<int, std::map<std::string, float>> cacheseverity();


#endif