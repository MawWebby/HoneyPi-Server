// MARIADB DECLARATIONS AND FUNCTIONS
#include <string>


#ifndef MARIADBFUNCTIONS_H
#define MARIADBFUNCTIONS_H


//  FUNCTION                            
int mariadb_ping();
int mariadb_ADDIPADDR(std::string);
int mariadb_CHECKIPADDR(std::string);
int mariadb_BLOCKIPADDR(std::string);
int mariadb_UNBLOCKIPADDR(std::string);
int mariaDB_ADDPACKETTOIPADDR(std::string);
int mariadb_REMOVEPACKETFROMIPADDR(std::string);
bool mariadb_READDEVBLOCK(std::string);
int mariadb_REMOVEOLDIPAADR(std::string);
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

#endif