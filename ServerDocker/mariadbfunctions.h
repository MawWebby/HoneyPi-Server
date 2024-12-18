// MARIADB DECLARATIONS AND FUNCTIONS
#include <string>


#ifndef MARIADBFUNCTIONS_H
#define MARIADBFUNCTIONS_H


//  FUNCTION                            
int mariadb_ping();                                               // MARIADB STATUS PING
int mariadb_ADDIPADDR(std::string);                               // ADD IP ADDRESS IN SERVERSECURITY
int mariadb_CHECKIPADDR(std::string);                             // CHECK IP ADDRESS IN SERVERSECURITY
int mariadb_BLOCKIPADDR(std::string);                             // BLOCK IP ADDRESS IN SERVERSECURITY
int mariadb_UNBLOCKIPADDR(std::string);                           // UNBLOCK IP ADDRESS IN SERVERSECURITY
int mariadb_ADDPACKETTOIPADDR(std::string);                       // ADD PACKET TO IP IN SERVERSECURITY
int mariadb_REMOVEPACKETFROMIPADDR(std::string);                  // REMOVE PACKET FROM IP IN SERVER SECURITY
bool mariadb_READDEVBLOCK(std::string);                           // READ THE DEV BLOCK BAN
int mariadb_REMOVEOLDIPADDR(std::string);                         // REMOVE IP ADDRESS IN SERVERSECURITY
int mariadb_MAINTENANCE();
int mariadb_LASTTIMETOPACKET(std::string);
std::string mariadbREAD_VALUEPIAPI(std::string);
std::string mariadbREAD_VALUEROUTERAPI(std::string, int);
std::string mariadbREAD_EMAILADDRESS(std::string);
int mariadbRESET_PASSWORD(std::string, std::string, std::string);
bool mariadbPIAPI_keyvalid(std::string);
bool mariadbROUTERAPI_keyvalid(std::string);
int mariadbNEW_USER(std::string, std::string, std::string, std::string, std::string, std::string, std::string);
int mariadbINSERT_PIKEY(std::string, std::string);
int mariadbINSERT_ROUTERKEY(std::string, int, std::string);
bool mariadbVALIDATE_USER(std::string, std::string);
int mariadbINSERT_SESSIONKEY(std::string, std::string);
int mariadbCHECKIN_HONEYPI(std::string);
int mariadbROTATE_CREDENTIALShour();
int mariadbREMOVE_SESSIONTOKENS();
int mariadbROTATE_CREDENTIALSday();
int mariadbINVALIDATE_CREDENTIALS(std::string, std::string, std::string);
int mariadbRECEIVE_PAYMENT(std::string, bool);
int mariadbSET_PAYMENT(std::string, int);
int mariadbREMOVE_PIAPI(std::string);
int mariadbREMOVE_ROUTERAPI(std::string, int);
int mariadbREMOVE_USER(std::string, std::string);
int mariadbCHANGEPORTSTATUS(int, bool);
int mariadbREVIEWSTATUS();
int mariadbADDCOGTODB(std::string);
std::string mariadbTOPCOG();
int mariadbCLEARCOGS_START();
int mariadbCLEARCOGS_READ();
int mariadbSETCOGLOCKINDB();

// FUTURE LOOPS
// IPADDR
// LOOP TO SHOW ALL IPADDRESSES STORED IN SERVER SECURITY
// SET/REMOVE DEV BLOCK OF IPADDR
// READ # OF PACKETS

// CREDENTIALS

#endif