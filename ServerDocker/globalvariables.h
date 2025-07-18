#include <arpa/inet.h>              // SOCKET NETWORK OPERATIONS
#include <unistd.h>                 // STANDARD CHARSET!!!
#include <sys/socket.h>             // SOCKET PORT OPERATIONS
#include <string.h>                 // STD::STRINGS
#include <iostream>                 // INPUTS/OUTPUTS OPERATIONS
#include <fstream>                  // FILE STREAMS AND OPERATIONS
#include <thread>                   // MULTI-THREADING SUPPORT
#include <ctime>                    // TIME STRING
#include <random>                   // "RANDOM" STRING GENERATOR
#include <openssl/ssl.h>            // OPENSSL SSL STANDARD LIB
#include <openssl/err.h>            // OPENSSL CATCH EXCEPTIONS AND DEBUGGING FOR MORE DETAIL
#include <curl/curl.h>              // CURL STANDARD LIB FOR UPDATES
#include <curl/easy.h>              // CURL EASY MODE FOR UPDATES
#include <map>                      // STD::MAP VARIABLES AND TABLES
#include <csignal>                  // DOCKER CATCH SIGNALS
#include <fcntl.h>                  // USED FOR NON-BLOCKING SIGNALS!
#include <atomic>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/types.h>
#include <sys/stat.h>

// LINK TO OTHER FILES
#include "adminconsole.h"
#include "standardloops.h"
#include "servermaintenance.h"
#include "backup.h"
#include "network.h"
#include "Databases/encryption.h"
#include "handleapi.h"
#include "handlehttps.h"
#include "process.h"
#include "Databases/jsonfunctions.h"

// SERVER SIGNALS
extern std::atomic<int> stopSIGNAL;
extern std::atomic<int> updateSIGNAL;
extern std::atomic<int> serverStarted;
extern std::atomic<int> lockP80;
extern std::atomic<int> lockP443;
extern std::atomic<int> lockP11829;
extern std::atomic<int> statusP80;
extern std::atomic<int> statusP443;
extern std::atomic<int> statusP11829;
extern std::atomic<int> serverErrors;
extern std::atomic<int> debug;

// STATUS NUMBERS
extern std::atomic<long long int> apiRejects;
extern std::atomic<long long int> newConnections;
extern std::atomic<long long int> totalDevicesConnected;
extern std::atomic<long long int> processingErrors;
extern std::atomic<long long int> conversionErrors;
extern std::atomic<long long int> dataEncryptionErrors;
extern std::atomic<long long int> invalidPackets;
extern std::atomic<long long int> analyzedPackets;
extern std::atomic<long long int> clientsDenied;
extern std::atomic<long long int> cogsAnalyzed;
extern std::atomic<long long int> networkErrors;
extern std::atomic<long long int> encryptionchange;
extern std::atomic<long long int> readwriteoperationfail;
extern std::atomic<long long int> entryAdded;

// UPDATE VARIABLES
extern std::string updatesforSERVER;
extern std::string updatesforHONEYPI;

// SERVER VERSION
extern std::string honeyversion;
extern std::string jsonversion;

// IP BLOCKING/PACKETS MAP
extern std::map<std::string, int> ip11829;
extern std::map<std::string, int> ip443;

// HONEYPOT MAP
extern std::map <std::string, std::string>honeypotauthtotoken;
extern std::map <std::string, std::string>previoushoneypotauth;
extern std::map <std::string, std::string>previoushoneypotauth2;

// DATABASE LOCKS
extern std::atomic<int> jsonDBLock;
extern std::atomic<int> processDBLock;

// PACKET SPAM
extern int packetspam;

// TIMING VARIABLES
extern std::atomic<long long int> timer0;
extern std::atomic<long long int> timer1;
extern std::atomic<long long int> timer2;
extern std::atomic<long long int> timer3;
extern std::atomic<long long int> timer4;
extern std::atomic<long long int> timer5;
extern std::atomic<long long int> timer6;
extern std::atomic<long long int> timer7;
extern std::atomic<long long int> timer8;
extern std::atomic<long long int> timer9;
extern std::atomic<long long int> timer10;
extern std::atomic<long long int> startuptime;
extern std::atomic<long long int> currenttime;
extern std::atomic<long long int> timesincestartup;
extern std::atomic<int> calculatingtime;

////////////////////////////////////////////////
// COMMAND/FILES/AND OTHER MAPS FOR REPORTING //
////////////////////////////////////////////////

// "bash"
//extern std::map<std::string, float> commandseveritymap;
extern std::atomic<std::string> commandseveritymap2;

// "/home"
extern std::map<std::string, float> fileaccessseveritymap;

// "ADD uishfes INTO /home/test.txt:1"
extern std::map<std::string, float> fileeditsseveritymap;

// "/home/test.txt"
extern std::map<std::string, float> filechangesseveritymap;