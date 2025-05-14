#include "network.h"
#include "globalvariables.h"




//////////////////////
//// PING NETWORK ////
//////////////////////
int pingnetwork() {
    return system("ping -c 5 8.8.8.8 > nul:");
}



////////////////////////////////
////////////////////////////////
//// CURL/UPDATE OPERATIONS ////
////////////////////////////////
////////////////////////////////
// WRITE CALLBACK FOR SERVER DEVICE CHECK
size_t write_callbackserver(char *charactertoadd, size_t size, size_t nmemb, void *userdata) {
    std::string currentupdatereceived = updatesforSERVER;
    currentupdatereceived = currentupdatereceived + charactertoadd;
    updatesforSERVER = currentupdatereceived;
    return currentupdatereceived.length();
}

// WRITE CALLBACK FOR CLIENT DEVICE CHECK
size_t write_callbackhoneypi(char *charactertoadd, size_t size, size_t nmemb, void *userdata) {
    std::string currentupdatehoney = updatesforHONEYPI;
    currentupdatehoney = currentupdatehoney + charactertoadd;
    updatesforHONEYPI = currentupdatehoney;
    return currentupdatehoney.length();
}



// CURL FOR SERVER DEVICE CHECK
void checkforserverupdates() {
    CURL *curl = curl_easy_init();
    char errcurlno[CURL_ERROR_SIZE];
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errcurlno);
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/server.txt");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callbackserver);

        // PERFORM CURL
        res = curl_easy_perform(curl);
        //std::cout << "RECEIVED GITHUB INFORMATION: " << updatefileinformationserver << std::endl;

        std::string updatefileinformationserver = updatesforSERVER;
        if (updatefileinformationserver == "") {
            logcritical("RECEIVED NULL INSTANCE FOR SERVER VERSION! - ", false);
            sendtologopen(errcurlno, false);
            sendtologopen(" - ", false);
            sendtolog(curl_easy_strerror(res), false);
            networkErrors.fetch_add(1);
        }
    
        // CLEAN UP CURL COMMAND
        curl_easy_cleanup(curl);
    } else {
        logcritical("AN ERROR OCCURRED IN CURL - ", false);
        sendtologopen(errcurlno, false);
        sendtologopen(" - ", false);
        sendtolog(curl_easy_strerror(res), false);
        networkErrors.fetch_add(1);
    }
}

// CURL FOR CLIENT DEVICE CHECK
void checkforhoneypiupdates() {
    CURL *curl = curl_easy_init();
    char errcurlno[CURL_ERROR_SIZE];
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errcurlno);
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://raw.githubusercontent.com/MawWebby/HoneyPi/main/Versions/mainversion.txt");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callbackhoneypi);

        // PERFORM CURL
        res = curl_easy_perform(curl);
        //std::cout << "RECEIVED GITHUB INFORMATION: " << updatefileinformationhoneypi << std::endl;

        std::string updatefileinformationhoneypi = updatesforHONEYPI;
        if (updatefileinformationhoneypi == "") {
            logcritical("RECEIVED NULL INSTANCE FOR CLIENT VERSION! - ", false);
            sendtologopen(errcurlno, false);
            sendtologopen(" - ", false);
            sendtolog(curl_easy_strerror(res), false);
            networkErrors.fetch_add(1);
        }
    
        // CLEAN UP CURL COMMAND
        curl_easy_cleanup(curl);
    } else {
        logcritical("AN ERROR OCCURRED IN CURL - ", false);
        sendtologopen(errcurlno, false);
        sendtologopen(" - ", false);
        sendtolog(curl_easy_strerror(res), false);
        networkErrors.fetch_add(1);
    }
}
