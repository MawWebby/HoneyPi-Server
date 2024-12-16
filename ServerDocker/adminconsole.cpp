#include "adminconsole.h"
#include "globalvariables.h"

void processCommand(const std::string& command) {

    bool foundcommand = false;
    if (command == "commands") {
        loginfo("", true);
    }

    if (command == "custom_command") {
        std::cout << "[APP] Executing custom command...\n";
    } else if (command == "exit") {
        std::cout << "[APP] Exiting...\n";
        exit(0);
    } else {
        std::cout << "Unknown command: " << command << "\n";
        std::cout << "Try 'commands' instead" << std::endl;
    }
}

void interactiveTerminal() {
    std::cout << "[TERMINAL] Interactive mode. Type 'exit' to quit.\n";

    while (true) {
        std::string command;
        std::cout << ">> ";
        std::getline(std::cin, command);

        if (!command.empty()) {
            processCommand(command);
        }
    }
}