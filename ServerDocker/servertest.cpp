//////////////////
// Dependencies //
//////////////////
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

// Atomic stop flag to ensure thread-safe access
std::atomic<bool> stop(false);

void handleSignal(int signal) {
    if (signal == SIGTERM || signal == SIGINT) {
        std::cout << "Received termination signal, shutting down gracefully..." << std::endl;
        
        stop.store(true);

        sleep(9);
        
        // SAVE LOGIC HERE
        // servershutdown();       
    }
}

// Function for the worker thread that will run in a loop
void workerThread() {
    while (!stop.load()) {
        std::cout << "Worker thread 1 is running..." << std::endl;
        sleep(1);
    }
    std::cout << "Worker thread is stopping." << std::endl;
}

void workerThread2() {
    while (!stop.load()) {  // Continuously check the stop flag
        std::cout << "Worker thread 2 is running..." << std::endl;
        sleep(1);
    }
    std::cout << "Worker thread 2 is stopping." << std::endl;
}

int main() {
    
    signal(SIGTERM, handleSignal);
    signal(SIGINT, handleSignal);

    // Launch a separate worker thread
    std::thread worker(workerThread);
    worker.detach();

    std::thread worker2(workerThread2);
    worker2.detach();


    // Wait for the worker thread to finish
    //worker.join();

    while (!stop.load()) {  // Continuously check the stop flag
        std::cout << "Main thread is running..." << std::endl;
        sleep(1);
    }
    std::cout << "Main thread is stopping." << std::endl;
    
    std::cout << "Main thread finished." << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}
