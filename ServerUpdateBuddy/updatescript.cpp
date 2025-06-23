// MAIN SIMPLE UPDATE SCRIPT
// Matthew Whitworth (MawWebby)
#include <unistd.h>
#include <string>
#include <iostream>

std::string buddyversion = "1";

// MADE FOR SERVER VERSIONS 0.X - 1.X
// NORMAL RETURN VALUE
// 0 => COMPLETED SUCCESSFULLY

// ERROR RETURN VALUES
// -1 => Download Failed (Main)
// -2 => Download Failed (SSH)
// -3 => Restart Failed (Main)

int main() {
    std::cout << "UPDATING SERVER TO NEW VERSION" << std::endl;
    std::cout << "ServerUpdateBuddyV" << buddyversion << std::endl;
    std::cout << "UPDATE - (  0%) - Waiting 15 seconds before continuing..." << std::endl;
    sleep(15);
    std::string systemcapable = "docker container stop HoneyPiMain && docker container rm HoneyPiMain &> /dev/null";


    // Stop Main Honeypot
    std::cout << "UPDATE - (  0%) - Stopping Server" << std::endl;
    std::string stopmain = "docker stop honeypiserver &> /dev/null";
    if (system(stopmain.c_str()) != 0) {
        return -4;
    }


    sleep(15);


    // DOWNLOADING NEW MAIN CONTAINER
    std::cout << "UPDATE - ( 10%) - Downloading New Main Docker" << std::endl;
    std::string downloadnewermaindocker = "docker pull mawwebby/honeypiserver:latest &> /dev/null";
    if (system(downloadnewermaindocker.c_str()) != 0) {
        std::cout << "ERROR - UNABLE TO UPDATE! COULD NOT DOWNLOAD NEWER VERSION OF MAIN DOCKER!" << std::endl;
        return -1;
    }


    sleep(5);


    // RESTART MAIN DOCKER CONTAINER
    std::cout << "UPDATE - ( 70%) - Starting New Server" << std::endl;
    std::string dockernewcommand = "docker run -d -it -v /home/pi/.docker:/root/.docker/ -v /home/pi/honeynvme/current/listfiles:/home/listfiles -v /home/pi/honeynvme/serverdump:/home/serverdump -v /home/pi/honeynvme/current/htmlmain:/home/htmlmainweb -v /home/pi/honeynvme/cogs:/home/crashlogs -p 80:80 -p 443:443 -p 11829:11829 -p 11830:11830 -p 22221:22221 -v /var/run/docker.sock:/var/run/docker.sock --name honeypiserver --rm mawwebby/honeypiserver:latest &> /dev/null";
    if (system(dockernewcommand.c_str()) != 0) {
        return -6;
    }


    sleep(2);


    std::cout << "UPDATE - (100%) - UPDATE COMPLETE!" << std::endl;


    sleep(2);


    return 0;
}