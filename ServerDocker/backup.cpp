#include "globalvariables.h"
#include "backup.h"


// CALLED METHOD
// 0 - SYSTEM
// 1 - ADMIN CONSOLE


//////////////////////
//// START BACKUP ////
//////////////////////
int startbackup(int calledmethod) {
    jsonDBLock.store(1);

    // MOVE ALL CONFIG AND JSON FILES TO BACKUP AND STORE THEM







    jsonDBLock.store(0);
    return 0;
}