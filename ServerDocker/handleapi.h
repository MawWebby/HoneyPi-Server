// HANDLE API MAIN FILE
#include <string>




#ifndef HANDLEAPI_H
#define HANDLEAPI_H 

int processAPI(int clientID, std::string header1, std::string data1, std::string header2, 
               std::string data2, std::string header3, std::string data3, 
               std::string header4, std::string data4, std::string header5, 
               std::string data5, std::string header6, std::string data6, 
               std::string header7, std::string data7, std::string header8, 
               std::string data8, std::string header9, std::string data9);

int analyzeAPIandexecute(int clientID, std::string messageA);

void apiconnectionthread(int clientID, std::string a11829, std::string b11829, std::string c11829);

void handle11829Connections(int server_fd4);

#endif