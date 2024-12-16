#include <arpa/inet.h>              // SOCKET NETWORK OPERATIONS
#include <unistd.h>                 // STANDARD CHARSET!!!
#include <sys/socket.h>             // SOCKET PORT OPERATIONS
#include <string.h>                 // STD::STRINGS
#include <iostream>                 // INPUTS/OUTPUTS OPERATIONS
#include <fstream>                  // FILE STREAMS AND OPERATIONS
#include <thread>                   // MULTI-THREADING SUPPORT
#include <ctime>                    // TIME STRING
#include <random>                   // "RANDOM" STRING GENERATOR
#include <mariadb/conncpp.hpp>      // MARIADB C++ CONNECTOR TO DB
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
#include "mariadbfunctions.h"
#include "servermaintenance.h"