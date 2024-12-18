#include "encryption.h"
#include "globalvariables.h"



// UCRYPT COG - 1
std::map<std::string, int> eecryptcog = {
    {"A", 0},
    {"B", 1},
    {"C", 2},
    {"D", 3},
    {"E", 4},
    {"F", 5},
    {"G", 6},
    {"H", 7},
    {"I", 8},
    {"J", 9},
    {"K", 10},
    {"L", 11},
    {"M", 12},
    {"N", 13},
    {"O", 14},
    {"P", 15},
    {"Q", 16},
    {"R", 17},
    {"S", 18},
    {"T", 19},
    {"U", 20},
    {"V", 21},
    {"W", 22},
    {"X", 23},
    {"Y", 24},
    {"Z", 25},
    {"a", 26},
    {"b", 27},
    {"c", 28},
    {"d", 29},
    {"e", 30},
    {"f", 31},
    {"g", 32},
    {"h", 33},
    {"i", 34},
    {"j", 35},
    {"k", 36},
    {"l", 37},
    {"m", 38},
    {"n", 39},
    {"o", 40},
    {"p", 41},
    {"q", 42},
    {"r", 43},
    {"s", 44},
    {"t", 45},
    {"u", 46},
    {"v", 47},
    {"w", 48},
    {"x", 49},
    {"y", 50},
    {"z", 51},
    {"0", 52},
    {"1", 53},
    {"2", 54},
    {"3", 55},
    {"4", 56},
    {"5", 57},
    {"6", 58},
    {"7", 59},
    {"8", 60},
    {"9", 61},
    {";", 62},
    {":", 63},
    {"/", 64},
    {"`", 65},
    {"~", 66},
    {"[", 67},
    {"{", 68},
    {"(", 69},
    {")", 70},
    {"}", 71},
    {"]", 72},
    {"?", 73},
    {"%", 74},
    {"!", 75},
};

// UCRYPT COG - 2
std::map<int, std::string> uecryptcog = {
    {0, "A"},
    {1, "B"},
    {2, "C"},
    {3, "D"},
    {4, "E"},
    {5, "F"},
    {6, "G"},
    {7, "H"},
    {8, "I"},
    {9, "J"},
    {10, "K"},
    {11, "L"},
    {12, "M"},
    {13, "N"},
    {14, "O"},
    {15, "P"},
    {16, "Q"},
    {17, "R"},
    {18, "S"},
    {19, "T"},
    {20, "U"},
    {21, "V"},
    {22, "W"},
    {23, "X"},
    {24, "Y"},
    {25, "Z"},
    {26, "a"},
    {27, "b"},
    {28, "c"},
    {29, "d"},
    {30, "e"},
    {31, "f"},
    {32, "g"},
    {33, "h"},
    {34, "i"},
    {35, "j"},
    {36, "k"},
    {37, "l"},
    {38, "m"},
    {39, "n"},
    {40, "o"},
    {41, "p"},
    {42, "q"},
    {43, "r"},
    {44, "s"},
    {45, "t"},
    {46, "u"},
    {47, "v"},
    {48, "w"},
    {49, "x"},
    {50, "y"},
    {51, "z"},
    {52, "0"},
    {53, "1"},
    {54, "2"},
    {55, "3"},
    {56, "4"},
    {57, "5"},
    {58, "6"},
    {59, "7"},
    {60, "8"},
    {61, "9"},
    {62, ";"},
    {63, ":"},
    {64, "/"},
    {65, "`"},
    {66, "~"},
    {67, "["},
    {68, "{"},
    {69, "("},
    {70, ")"},
    {71, "}"},
    {72, "]"},
    {73, "?"},
    {74, "%"},
    {75, "!"},
};





// DETERMINE ENCRYPTION METHOD
int encryptionmethod(std::string data, int called) {
    if (data.length() >= 8) {
        std::string firstvar = data.substr(0,1);
        std::string secondvar = data.substr(1,1);
        std::string thirdvar = data.substr(2,1);
        std::string fourthvar = data.substr(3,1);
        std::string fifthvar = data.substr(4,1);
        if (secondvar == "x" && fifthvar == "/") {
            // HACKSWEEP ENCRYPTION
            return 1;
        } else if (firstvar == secondvar && firstvar == thirdvar && firstvar == fourthvar && firstvar == fifthvar) {
            // UCRYPT ENCYPTION
            return 2;
        } else {
            if (called == 1) {
                std::cout << "RECEIVED INVALID RESPONSE!" << std::endl;
                std::cout << "SECOND VAR: " << secondvar << std::endl;
                std::cout << "FIFTH VAR: " << fifthvar << std::endl;
            } 
            logwarning("ENCRYPTION METHOD - Received Invalid Data", true);
            return 100;
        }
    } else {
        logwarning("NO VALID DATA RECEIVED FOR ENCRYPTION METHOD!", true);
        return 255;
    }
    return 255;
}




// HACKSWEEP ENCRYPTION
std::string hacksweep_decrypt(std::string data) {

}

std::string hacksweep_Ecrypt(std::string data) {

}




// UCRYPT ENCRYPTION
std::string ucrypt_decrypt(std::string data) {
    std::string newmessage = "";
    if (data.length() >= 6) {
        std::string key = data.substr(0,5);
        std::string values = data.substr(5, data.length() - 5);
        int keytime = 15;
        if (key == "vvvvv") {
            keytime = 5;
        } else if (key == "wwwww") {
            keytime = 4;
        } else if (key == "xxxxx") {
            keytime = 3;
        } else if (key == "yyyyy") {
            keytime = 2;
        } else if (key == "zzzzz") {
            keytime = 1;
        } else if (key == "AAAAA") {
            keytime = -1;
        } else if (key == "BBBBB") {
            keytime = -2;
        } else if (key == "CCCCC") {
            keytime = -3;
        } else if (key == "DDDDD") {
            keytime = -4;
        } else if (key == "EEEEE") {
            keytime = -5;
        }

        // ACTUALLY DECODE NOW
        if (keytime != 15) {
            int valuelength = values.length();
            int currentvalue = 0;
            std::string currentcharacter = "";
            while (currentvalue < valuelength) {
                currentcharacter = values.substr(currentvalue, 1);
                int valuefromkey = eecryptcog.find(currentcharacter)->second;
                if (valuefromkey >= 0) {
                    valuefromkey = valuefromkey + keytime;
                    if (valuefromkey < 0) {
                        valuefromkey = valuefromkey + 76;
                    } else if (valuefromkey > 75) {
                        valuefromkey = valuefromkey - 76;
                    }
                    std::string valueofnewcharacter = uecryptcog.find(valuefromkey)->second;
                    newmessage = newmessage + valueofnewcharacter;
                } else {
                    newmessage = newmessage + currentcharacter;
                }
                currentvalue = currentvalue + 1;
            }
        } else {
            return "ERROR";
        }
    } else {
        logwarning("Received Decryption Less than Key! (UCRYPT)", true);
        return "ERROR";
    }
    return newmessage;
}

std::string ucrypt_Ecrypt(std::string data) {
    std::string newmessage = "";
    int keyshift = rand() % 10 - 5; 
    if (keyshift == 0) {
        keyshift = rand() % 2 + 3;
    }
    switch (keyshift) {
        case -5:
            newmessage = "vvvvv";
            break;
        case -4:
            newmessage = "wwwww";
            break;
        case -3:
            newmessage = "xxxxx";
            break;
        case -2:
            newmessage = "yyyyy";
            break;
        case -1:
            newmessage = "zzzzz";
            break;
        case 1:
            newmessage = "AAAAA";
            break;
        case 2:
            newmessage = "BBBBB";
            break;
        case 3:
            newmessage = "CCCCC";
            break;
        case 4:
            newmessage = "DDDDD";
            break;
        case 5:
            newmessage = "EEEEE";
            break;
    }
    int datalength = data.length();
    int dataanalyzed = 0;
    std::string characterindata = "";
    while (dataanalyzed < datalength) {
        characterindata = data.substr(dataanalyzed, 1);
        auto search = eecryptcog.find(characterindata);
        int valueofchar = search->second;
        if (valueofchar >= 0) {
            valueofchar = valueofchar + keyshift;
            if (valueofchar < 0) {
                valueofchar = valueofchar + 76;
            } else if (valueofchar > 75) {
                valueofchar = valueofchar - 76;
            }
            std::string valueofnewcharacter = uecryptcog.find(valueofchar)->second;
            newmessage = newmessage + valueofnewcharacter;
        } else {
            newmessage = newmessage + characterindata;
        }
        dataanalyzed = dataanalyzed + 1;
    }
    return newmessage;
}