#include "globalvariables.h"
#include "backup.h"
#include "Databases/json.hpp"
using json = nlohmann::json;

// CALLED METHOD
// 0 - SYSTEM
// 1 - ADMIN CONSOLE

// RETURNS
// 0 => SUCCESS
// 100 => 
// 101 => 
// 102 => 
// 103 => 
// 104 => 
// 105 => 
// 106 => 
// 107 => 
// 108 => 
// 109 => 
// 110 => 
// 111 => 
// 112 => 
// 113 => 
// 114 => 
// 115 => 
// 116 => 
// 117 => 
// 118 => 
// 119 => 
// 120 => 
// 121 => 
// 122 => 
// 123 => 
// 124 => 
// 125 => 
// 126 => 
// 127 => 
// 128 => 
// 129 => 
// 130 => 
// 131 => 
//////////////////////
//// START BACKUP ////
//////////////////////
int startbackup(int calledmethod) {
    if (calledmethod == 1) {
        std::cout << "STARTING BACKUP" << std::endl;
        debug.store(1);
    }
    loginfo("BACKUP - Starting Backup!", true);



    sleep(3);



    loginfo("Locking DBs...", false);
    jsonDBLock.store(1);
    lockP80.store(1);
    lockP443.store(1);
    lockP11829.store(1);
    processDBLock.store(1);

    sleep(15);
    if (jsonDBLock.load() != 1 || lockP80.load() != 1 || lockP443.load() != 1 || lockP11829.load() != 1 || processDBLock.load() != 1) {
        return 101;
    }
    sendtolog("Done", true);



    loginfo("Opening Backup Location...", false);
    int calc = time(NULL);
    std::string backupfolderlocation = "/home/backups/SYSTEM_" + inttostring(calc);
    std::string mkdirbackup = "mkdir " + backupfolderlocation;
    int returns = system(mkdirbackup.c_str());
    if (returns != 0) {
        return 102;
    }
    sendtolog("Done", true);



    loginfo("Creating Backup Image...", false);
    std::string serverdump = backupfolderlocation + "/serverdump";
    std::string ipfiles = backupfolderlocation + "/ipFiles";
    std::string pendingprocesses = backupfolderlocation + "/pendingprocesses";
    std::string jsonfiles = backupfolderlocation + "/jsonfiles";
    std::string keyed = backupfolderlocation + "/keyed_information";
    std::string coglock = backupfolderlocation + "/coglock";
    std::string infofile = backupfolderlocation + "/stat.json";

    std::string MAKEserve = "mkdir " + serverdump;
    std::string MAKEip = "mkdir " + ipfiles;
    std::string MAKEproc = "mkdir " + pendingprocesses;
    std::string MAKEjs = "mkdir " + jsonfiles;
    std::string MAKEencry = "mkdir " + keyed;
    std::string MAKEcrog = "mkdir " + coglock;
    std::string MAKEfile = "touch " + infofile;
    sendtolog("Done", true);



    sleep(1);
    loginfo("Creating Backup Structure...", false);
    if (system(MAKEserve.c_str()) != 0) {
        return 103;
    }
    if (system(MAKEip.c_str()) != 0) {
        return 104;
    }
    if (system(MAKEproc.c_str()) != 0) {
        return 105;
    }
    if (system(MAKEjs.c_str()) != 0) {
        return 106;
    }
    if (system(MAKEencry.c_str()) != 0) {
        return 107;
    }
    if (system(MAKEcrog.c_str()) != 0) {
        return 108;
    }
    if (system(MAKEfile.c_str()) != 0) {
        return 109;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying Serverdump Files...", false);
    std::string cpS1 = "cp /home/serverdump/errors.txt " + serverdump + "/errors.txt";
    std::string cpS2 = "cp /home/serverdump/ipaccessed.txt " + serverdump + "/ip_ADDR_Accessed.txt";
    std::string cpS3 = "cp /home/serverdump/log.txt " + serverdump + "/logs.txt";
    std::string cpS4 = "cp /home/serverdump/login.txt " + serverdump + "/login_attempts.txt";
    std::string cpS5 = "cp /home/serverdump/packetlog.txt " + serverdump + "/packet_logs.txt";
    std::string cpS6 = "cp /home/serverdump/serverhistory.txt " + serverdump + "/server_history.txt";
    if (system(cpS1.c_str()) != 0) {
        return 110;
    }
    if (system(cpS2.c_str()) != 0) {
        return 111;
    }
    if (system(cpS3.c_str()) != 0) {
        return 112;
    }
    if (system(cpS4.c_str()) != 0) {
        return 113;
    }
    if (system(cpS5.c_str()) != 0) {
        return 114;
    }
    if (system(cpS6.c_str()) != 0) {
        return 115;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying IP Files...", false);
    std::string ipL1 = "cp /home/listfiles/iplistraw.txt " + ipfiles + "/ip_list_raw_more_info.txt";
    std::string ipL2 = "cp /home/listfiles/iplistsmoreinfo.txt " + ipfiles + "/ip_list_clean_more_info.txt";
    std::string ipL3 = "cp /home/listfiles/ipliststandard.txt " + ipfiles + "/ip_list_STANDARD.txt";
    std::string ipL4 = "cp /home/listfiles/ipstrict.txt " + ipfiles + "/ip_list_STRICT.txt";
    std::string ipL5 = "cp /home/listfiles/ipsafety.txt " + ipfiles + "/ip_SAFETY.txt";
    if (system(ipL1.c_str()) != 0) {
        return 116;
    }
    if (system(ipL2.c_str()) != 0) {
        return 117;
    }
    if (system(ipL3.c_str()) != 0) {
        return 118;
    }
    if (system(ipL4.c_str()) != 0) {
        return 119;
    }
    if (system(ipL5.c_str()) != 0) {
        return 120;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying Pending File...", false);
    std::string servd = "cp /home/serverdump/serverdump.txt " + serverdump + "/pendingfile.txt";
    system(servd.c_str()) != 0;
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying JSON Files...", false);
    std::string cpJ1 = "cp /home/serverdump/yam.json " + jsonfiles + "/pass_json.json";
    std::string cpJ2 = "cp /home/serverdump/yaml.json " + jsonfiles + "/user_json.json";
    std::string cpJ3 = "cp /home/serverdump/yap.json " + jsonfiles + "/perm_api_json.json";
    std::string cpJ4 = "cp /home/serverdump/ycr.json " + jsonfiles + "/crydyt_json.json";
    std::string cpJ5 = "cp /home/serverdump/yfo.json " + jsonfiles + "/json_infos.json";
    std::string cpJ6 = "cp /home/serverdump/tempstring.json " + jsonfiles + "/temp_api_strings.json";
    std::string cpJ7 = "cp /home/serverdump/blk.json " + jsonfiles + "/MISC_json.json";
    if (system(cpJ1.c_str()) != 0) {
        return 121;
    }
    if (system(cpJ2.c_str()) != 0) {
        return 122;
    }
    if (system(cpJ3.c_str()) != 0) {
        return 123;
    }
    if (system(cpJ4.c_str()) != 0) {
        return 124;
    }
    if (system(cpJ5.c_str()) != 0) {
        return 125;
    }
    if (system(cpJ6.c_str()) != 0) {
        return 126;
    }
    if (system(cpJ7.c_str()) != 0) {
        return 127;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying List Information...", false);
    std::string cpList1 = "cp /home/listfiles/acpmac.txt " + keyed + "/MAC_APIs.txt";
    std::string cpList2 = "cp /home/listfiles/cmdrun.txt " + keyed + "/CMD_RUN.txt";
    std::string cpList3 = "cp /home/listfiles/extramap.txt " + keyed + "/EXTRA.txt";
    std::string cpList4 = "cp /home/listfiles/fileacc.txt " + keyed + "/Files_Accessed.txt";
    std::string cpList5 = "cp /home/listfiles/foldacc.txt " + keyed + "/Folders_Accessed.txt";
    std::string cpList6 = "cp /home/listfiles/maclist.txt " + keyed + "/File_Edits.txt";
    std::string cpList7 = "cp /home/listfiles/passstream.txt " + keyed + "/Password_Stream.txt";
    std::string cpList8 = "cp /home/listfiles/serverconfig1.txt " + keyed + "/SERVE.txt";
    std::string cpList9 = "cp /home/listfiles/severitylist.txt " + keyed + "/LIST.txt";
    std::string cpListA = "cp /home/listfiles/userstream.txt " + keyed + "/Username_Stream.txt";
    std::string cpListB = "cp /home/listfiles/serverdump.txt " + keyed + "/SD.txt";
    if (system(cpList1.c_str()) != 0) {
        return 128;
    }
    if (system(cpList2.c_str()) != 0) {
        return 129;
    }
    if (system(cpList3.c_str()) != 0) {
        return 130;
    }
    if (system(cpList4.c_str()) != 0) {
        return 131;
    }
    if (system(cpList5.c_str()) != 0) {
        return 132;
    }
    if (system(cpList6.c_str()) != 0) {
        return 133;
    }
    if (system(cpList7.c_str()) != 0) {
        return 134;
    }
    if (system(cpList8.c_str()) != 0) {
        return 135;
    }
    if (system(cpList9.c_str()) != 0) {
        return 136;
    }
    if (system(cpListA.c_str()) != 0) {
        return 137;
    }
    if (system(cpListB.c_str()) != 0) {
        return 138;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Copying COGS to Backup...", false);
    std::string cpCogs = "cp /home/crashlogs " + coglock + "/";
    if (system(cpCogs.c_str()) != 0) {
        return 139;
    }
    sendtolog("Done", true);



    sleep(2);
    loginfo("Creating STAT Json...", false);
    std::string touchJSON = "touch " + infofile;
    if (system(touchJSON.c_str()) != 0) {
        return 140;
    }
    std::ofstream jsonstat;
    jsonstat.open(infofile.c_str());
    if (jsonstat.is_open() != true) {
        return 141;
    }
    sendtolog("Done", true);


    sleep(2);
    loginfo("Finalizing STAT Json...", false);
    const time_t friendly = time(NULL);
    json statfile;
    statfile["PARMS"]["VERSION"] = honeyversion;
    statfile["PARMS"]["JSON"] = jsonversion;
    statfile["PARMS"]["NULL"] = "NULL";
    statfile["PARMS"]["TIME"] = ctime(&friendly);
    statfile["PARMS"]["TIME_T"] = inttostring(calc);
    statfile["PARMS"]["WATERMELON"] = "false";
    statfile["SERVERDUMP"] = "OK";
    statfile["IPFILES"] = "OK";
    statfile["PENDING_PROCESSES"] = "OK";
    statfile["KEYED"] = "OK";
    statfile["CRASHLOGS"] = "OK";
    statfile["INFOFILES"] = "OK";
    statfile["STATS"]["P80"] = "1";
    statfile["STATS"]["P443"] = "1";
    statfile["STATS"]["P11829"] = "1";
    statfile["STATS"]["JSON_LOCK"] = "1";
    statfile["STATS"]["NEW_Connects"] = inttostring(serverErrors.load());
    statfile["STATS"]["DEV_Connected"] = inttostring(serverErrors.load());
    statfile["STATS"]["Analyzed-Packets"] = inttostring(serverErrors.load());
    statfile["STATS"]["Analyzed-Cogs"] = inttostring(serverErrors.load());
    statfile["STATS"]["Encryptions"] = inttostring(serverErrors.load());
    statfile["STATS"]["JSON_DBs_Modified"] = inttostring(serverErrors.load());
    statfile["STATS"]["API_Reject"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_General"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Processing"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Conversion"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Encryption"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Invalid-Packet"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Clients-Denied"] = inttostring(serverErrors.load());
    statfile["STATS"]["ERROR_Network"] = inttostring(serverErrors.load());
    jsonstat << std::setw(4) << statfile << std::endl;
    jsonstat.close();
    sendtolog("Done", true);



    sleep(2);
    loginfo("Encrypt Files...", false);
    // ENCRYPT INFORMATION
    // FIX THIS





    // CLEAR DB FILES INTO AND REEVALUATE CHECKSUMS





    // FINALIZE AND ZIP THE FOLDER
    loginfo("Finalizing Backup...", false);




    sleep(3);
    loginfo("!!!Restoring Original State!!!", true);
    jsonDBLock.store(0);
    lockP80.store(0);
    lockP443.store(0);
    lockP11829.store(0);
    processDBLock.store(0);
    sleep(3);



    
    loginfo("Backup Completed Successfully at " + inttostring(calc) + " (" + ctime(&friendly) + ")", true);
    if (calledmethod == 1) {
        debug.store(0);
    }
    sleep(1);
    return 0;
}





/////////////////////////////
//// RESTORE FROM BACKUP ////
/////////////////////////////
int restorefrombackup(std::string backupname, std::string keyphrase) {
    // FIX THIS
    return 100;
}