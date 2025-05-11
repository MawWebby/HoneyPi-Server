#include "globalvariables.h"
#include "handlehttps.h"



// HTML VARIABLES
std::string mainhtmlpayload;
std::string pricinghtmlpayload;
std::string aboutpayload;
std::string getinfopayload;
std::string getstartedpayload;
std::string signuppayload;
std::string loginpayload;
std::string blogpayload;
std::string accountpayload;
std::string installhtmlpayload;
std::string installscriptSHpayload;
const std::string httpfail = "HTTP/1.0 504 OK\nContent-Type:text/html\nContent-Length: 30\n\n<h1>504: Gateway Time-Out</h1>";
const std::string httpforbidden = "HTTP/1.0 403 OK\nContent-Type:text/html\nContent-Length: 23\n\n<h1>403: Forbidden</h1>";
const std::string httpservererror = "HTTP/1.0 505 OK\nContent-Type:text/html\nContent-Length: 72\n\n<h1>505: An Internal Server Error Occurred, Please Try Again Later.</h1>";
const std::string httpnotfound = "HTTP/1.0 404 OK\nContent-Type:text/html\nContent-Length: 28\n\n<h1>404: Page Not Found</h1>";
const std::string serveraddress = "honeypi.baselinux.net";
const std::string httpsuccess = "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\nConnection: close\r\nContent-Length: ";



// HTML FILE LOCATIONS
const char* mainhtml = "/home/htmlmainweb/index.html";
const char* pricehtml = "/home/htmlmainweb/pricing.html";
const char* bloghtmlfile = "/home/htmlmainweb/blog.html";
const char* loginhtmlfile = "/home/htmlmainweb/login.html";
const char* TOSFreefilefile = "/home/htmlmainweb/TOSFree.html";
const char* TOSProfilefile = "/home/htmlmainweb/TOSPro.html";
const char* TOSEnterprisefile = "/home/htmlmainweb/TOSEnterprise.html";
const char* PrivacyPolicyfile = "/home/htmlmainweb/privacypolicy.html";
const char* getstartedfile = "/home/htmlmainweb/get-started.html";
const char* accountfile = "/home/htmlmainweb/account.html";
const char* installfile = "/home/htmlmainweb/install.html";
const char* installBASH = "/home/htmlmainweb/installscript.sh";
const char* htmlfolder = "/home/htmlmainweb";
const char* signuphtmlfile = "/home/htmlmainweb/signup.html";
const char* configpagehtml = "/home/htmlmainweb/config.html";




////////////////////////////
//// LOAD HTML INTO RAM ////
//////////////////////////// 

// PERMANENT LOAD INTO RAM!
int loadmainHTMLintoram() {
    std::string templine;
    std::ifstream htmlmain;
    mainhtmlpayload = "";
    htmlmain.open(mainhtml);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (htmlmain.is_open() == true) {
        while (completionht != true) {
            getline(htmlmain, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                mainhtmlpayload = mainhtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = mainhtmlpayload.length();
        mainhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + mainhtmlpayload;
        htmlmain.close();
        sendtolog("Done", false);
        return 0;
    } else {
        mainhtmlpayload = httpservererror;
        htmlmain.close();
        sendtolog("ERROR", true);
        return 1;
    }
    mainhtmlpayload = httpservererror;
    htmlmain.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadpricingHTMLintoram() {
    std::string templine;
    std::ifstream htmlprice;
    pricinghtmlpayload = "";
    htmlprice.open(pricehtml);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (htmlprice.is_open() == true) {
        while (completionht != true) {
            getline(htmlprice, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                pricinghtmlpayload = pricinghtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = pricinghtmlpayload.length();
        pricinghtmlpayload = httpsuccess + std::to_string(length) + beforepayload + pricinghtmlpayload;
        htmlprice.close();
        sendtolog("Done", false);
        return 0;
    } else {
        pricinghtmlpayload = httpservererror;
        htmlprice.close();
        sendtolog("ERROR", true);
        return 1;
    }
    pricinghtmlpayload = httpservererror;
    htmlprice.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadblogHTMLintoram() {
    std::string templine;
    std::ifstream bloghtml;
    blogpayload = "";
    bloghtml.open(bloghtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (bloghtml.is_open() == true) {
        while (completionht != true) {
            getline(bloghtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                blogpayload = blogpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = blogpayload.length();
        blogpayload = httpsuccess + std::to_string(length) + beforepayload + blogpayload;
        bloghtml.close();
        sendtolog("Done", false);
        return 0;
    } else {
        blogpayload = httpservererror;
        bloghtml.close();
        sendtolog("ERROR", true);
        return 1;
    }
    blogpayload = httpservererror;
    bloghtml.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadloginHTMLintoram() {
    std::string templine;
    std::ifstream loginhtml;
    loginpayload = "";
    loginhtml.open(loginhtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (loginhtml.is_open() == true) {
        while (completionht != true) {
            getline(loginhtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                loginpayload = loginpayload + templine + "\n";
            }
        }
        // Connection: close\r\n
        std::string beforepayload = "\n\n";
        int length = loginpayload.length();
        loginpayload = httpsuccess + std::to_string(length) + beforepayload + loginpayload;
        loginhtml.close();
        sendtolog("Done", false);
        return 0;
    } else {
        loginpayload = httpservererror;
        loginhtml.close();
        sendtolog("ERROR", true);
        return 1;
    }
    loginpayload = httpservererror;
    loginhtml.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadsignupHTMLintoram() {
    std::string templine;
    std::ifstream signuphtml;
    signuppayload = "";
    signuphtml.open(signuphtmlfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (signuphtml.is_open() == true) {
        while (completionht != true) {
            getline(signuphtml, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                signuppayload = signuppayload + templine + "\n";
            }
        }
        std::string beforepayload = "\n\n";
        int length = signuppayload.length();
        signuppayload = httpsuccess + std::to_string(length) + beforepayload + signuppayload;
        signuphtml.close();
        sendtolog("Done", false);
        return 0;
    } else {
        loginpayload = httpservererror;
        signuphtml.close();
        sendtolog("ERROR", true);
        return 1;
    }
    loginpayload = httpservererror;
    signuphtml.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadgetstartedHTMLintoram() {
    std::string templine;
    std::ifstream getstartedstream;
    getstartedpayload = "";
    getstartedstream.open(getstartedfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (getstartedstream.is_open() == true) {
        while (completionht != true) {
            getline(getstartedstream, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                getstartedpayload = getstartedpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = getstartedpayload.length();
        getstartedpayload = httpsuccess + std::to_string(length) + beforepayload + getstartedpayload;
        getstartedstream.close();
        sendtolog("Done", false);
        return 0;
    } else {
        getstartedpayload = httpservererror;
        getstartedstream.close();
        sendtolog("ERROR", true);
        return 1;
    }
    getstartedpayload = httpservererror;
    getstartedstream.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadaccountHTMLintoram() {
    std::string templine;
    std::ifstream accountpayloadfile;
    accountpayload = "";
    accountpayloadfile.open(accountfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (accountpayloadfile.is_open() == true) {
        while (completionht != true) {
            getline(accountpayloadfile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                accountpayload = accountpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = accountpayload.length();
        accountpayload = httpsuccess + std::to_string(length) + beforepayload + accountpayload;
        accountpayloadfile.close();
        sendtolog("Done", false);
        return 0;
    } else {
        accountpayload = httpservererror;
        accountpayloadfile.close();
        sendtolog("ERROR", true);
        return 1;
    }
    accountpayload = httpservererror;
    accountpayloadfile.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadinstallHTMLintoram() {
    std::string templine;
    std::ifstream installHTMLFile;
    installhtmlpayload = "";
    installHTMLFile.open(installfile);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (installHTMLFile.is_open() == true) {
        while (completionht != true) {
            getline(installHTMLFile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                installhtmlpayload = installhtmlpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = installhtmlpayload.length();
        installhtmlpayload = httpsuccess + std::to_string(length) + beforepayload + installhtmlpayload;
        installHTMLFile.close();
        sendtolog("Done", false);
        return 0;
    } else {
        installhtmlpayload = httpservererror;
        installHTMLFile.close();
        sendtolog("ERROR", true);
        return 1;
    }
    installhtmlpayload = httpservererror;
    installHTMLFile.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadinstallscriptSHHTMLintoram() {
    std::string templine;
    std::ifstream installSHFile;
    installscriptSHpayload = "";
    installSHFile.open(installBASH);
    bool completionht = false;
    int timer7 = 0;
    int timer7max = 5;
    if (installSHFile.is_open() == true) {
        while (completionht != true) {
            getline(installSHFile, templine);
            if (templine == "" || templine == "</html>") {
                timer7 = timer7 + 1;
                if (timer7 >= timer7max) {
                    completionht = true;
                }
            } else {
                installscriptSHpayload = installscriptSHpayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = installscriptSHpayload.length();
        installscriptSHpayload = httpsuccess + std::to_string(length) + beforepayload + installscriptSHpayload;
        installSHFile.close();
        sendtolog("Done", false);
        return 0;
    } else {
        installscriptSHpayload = httpservererror;
        installSHFile.close();
        sendtolog("ERROR", true);
        return 1;
    }
    installscriptSHpayload = httpservererror;
    installSHFile.close();
    sendtolog("ERROR", true);
    return 1;
}

int loadHTMLINTORAM() {
    loginfo("HTML - Loading All Main HTML Pages into RAM!", true);
    int returnvalue = 0;
    loginfo("HTML - Loading index.html into RAM...", false);
    returnvalue = returnvalue + loadmainHTMLintoram();
    loginfo("HTML - Loading pricing.html into RAM...", false);
    returnvalue = returnvalue + loadpricingHTMLintoram();
    loginfo("HTML - Loading blog.html into RAM...", false);
    returnvalue = returnvalue + loadblogHTMLintoram();
    loginfo("HTML - Loading login.html into RAM...", false);
    returnvalue = returnvalue + loadloginHTMLintoram();
    loginfo("HTML - Loading signup.html into RAM...", false);
    returnvalue = returnvalue + loadsignupHTMLintoram();
    loginfo("HTML - Loading getstarted.html into RAM...", false);
    returnvalue = returnvalue + loadgetstartedHTMLintoram();
    loginfo("HTML - Loading account.html into RAM...", false);
    returnvalue = returnvalue + loadaccountHTMLintoram();
    loginfo("HTML - Loading install.html into RAM...", false);
    returnvalue = returnvalue + loadinstallHTMLintoram();
    loginfo("HTML - Loading installscript.sh into RAM...", false);
    returnvalue = returnvalue + loadinstallscriptSHHTMLintoram();

    // returnvalue = returnvalue + 
    loginfo("HTML - Finishing Loading into RAM...", false);

    if (returnvalue != 0) {
        sendtolog("ERROR", true);
        logwarning("HTML - LOADING INTO RAM RETURNED VALUE - " + std::to_string(returnvalue) + " - Continuing", false);
    } else {
        sendtolog("DONE", false);
    }
    return returnvalue;
}


// TEMPORARY READS
std::string readTOSFree() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSFreefilefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readTOSPro() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSProfilefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readTOSEnterprise() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(TOSEnterprisefile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}

std::string readPrivacyPolicy() {
    std::string templine;
    std::ifstream tosfreestream;
    std::string tospayload = "";
    tosfreestream.open(PrivacyPolicyfile);
    bool completionhy = false;
    int timer8 = 0;
    int timer8max = 0;
    if (tosfreestream.is_open() == true) {
        while (completionhy != true) {
            getline(tosfreestream, templine);
            if (templine == "" || templine == "</html>") {
                timer8 = timer8 + 1;
                if (timer8 >= timer8max) {
                    completionhy = true;
                }
            } else {
                tospayload = tospayload + templine;
            }
        }
        std::string beforepayload = "\n\n";
        int length = tospayload.length();
        tospayload = httpsuccess + std::to_string(length) + beforepayload + tospayload;
        tosfreestream.close();
        return tospayload;
    } else {
        tosfreestream.close();
        return httpservererror;
    }
    tosfreestream.close();
    return httpservererror;
}







//////////////////////////////////////////////////////////////
// HANDLE NETWORKED CONNECTIONS (443) - MAIN HTTPS SERVER!! //
//////////////////////////////////////////////////////////////
void httpsconnectionthread(SSL *ssl, char client_ip[INET_ADDRSTRLEN], int client_fd, struct sockaddr_in client_addr) {
    loginfo("HTTPS THREAD", true);
    std::string ipaddr;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "/certs/server.crt", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "/certs/private.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return;
    }

    loginfo("True through ssl checks", true);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        logwarning("SSL_ACCEPT NOT TRUE!", true);
    } else {
        // Buffer to read the incoming request
        char buffer[2048] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        int timer89 = 0;
        int timer89max = 5;
        bool completed23 = false;
        std::string bufferstring = buffer;
        if (bufferstring != "" && bytes_read >= 7 && sizeof(buffer) >= 7) {
            std::string headerrequest = bufferstring.substr(0,4);
            
            if (bufferstring.length() >= 7) {
                // CHANGE HERE FROM GET: / TO GET /
                logcritical(headerrequest, true);
                if (headerrequest == "GET ") {
                    std::string maindirectory = bufferstring.substr(4,1);

                    // MAKE SURE THAT THE ADDRESS IS VALID
                    if (maindirectory == "/") {
                        std::string nextletter = bufferstring.substr(5,2);

                        // MAKE SURE A CONNECTION WAS RECEIVED!
                        bool pagefound = false;

                        // MAIN PAGE
                        if (nextletter == " H") {
                            SSL_write(ssl, mainhtmlpayload.c_str(),mainhtmlpayload.length());
                            //int send_res=send(new_socket,mainhtmlpayload.c_str(),mainhtmlpayload.length(),0);
                            pagefound = true;
                        }

                        // INDEX.HTML
                        if (nextletter == "in") {
                            //index.html
                            std::string indexfulldictionary = bufferstring.substr(5, 10);
                            if (indexfulldictionary == "index.html") {
                                SSL_write(ssl,mainhtmlpayload.c_str(),mainhtmlpayload.length());
                                pagefound = true;
                            }
                        }

                        // PRICING.HTML
                        if (nextletter == "pr") {
                            // pricing.html
                            std::string pricingfulldictionary = bufferstring.substr(5,12);
                            if (pricingfulldictionary == "pricing.html") {
                                SSL_write(ssl,pricinghtmlpayload.c_str(),pricinghtmlpayload.length());
                                pagefound = true;
                            }
                        }

                        // BLOG.HTML
                        if (nextletter == "bl") {
                            // blog.html
                            std::string blogfulldictionary = bufferstring.substr(5,9);
                            if (blogfulldictionary == "blog.html") {
                                SSL_write(ssl,blogpayload.c_str(),blogpayload.length());
                                pagefound = true;
                            }
                        }

                        // LOGIN.HTML
                        if (nextletter == "lo") {
                            // login.html
                            std::string loginfulldictionary = bufferstring.substr(5,10);
                            if (loginfulldictionary == "login.html") {
                                SSL_write(ssl,loginpayload.c_str(),loginpayload.length());
                                pagefound = true;
                            }
                        }

                        // TERMS OF SERVICE
                        if (nextletter == "TO") {
                            // TOSFree.html
                            // TOSPro.html
                            // TOSEnterprise.html
                            std::string TOSfulldictionary = bufferstring.substr(5, 11);

                            // TOSFREE.HTML
                            if (TOSfulldictionary == "TOSFree.htm") {
                                std::string tospayload = readTOSFree();
                                SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }

                            // TOSPRO.HTML
                            if (TOSfulldictionary == "TOSPro.html") {
                                std::string tospayload = readTOSPro();
                                SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }

                            // TOSEnterpri
                            if (TOSfulldictionary == "TOSEnterpri") {
                                std::string tospayload = readTOSEnterprise();
                                SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }
                        }

                        // PRIVACY POLICY
                        if (nextletter == "pr") {
                            // privacypolicy.html
                            std::string privacyfulldictionary = bufferstring.substr(5,18);
                            if (privacyfulldictionary == "privacypolicy.html") {
                                std::string tospayload = readPrivacyPolicy();
                                SSL_write(ssl,tospayload.c_str(),tospayload.length());
                                pagefound = true;
                            }
                        }

                        // GET-STARTED.HTML
                        if (nextletter == "ge") {
                            // GET-STARTED.HTML
                            std::string getstartedfulldictionary = bufferstring.substr(5,16);
                            if (getstartedfulldictionary == "get-started.html") {
                                SSL_write(ssl,getstartedpayload.c_str(),getstartedpayload.length());
                                pagefound = true;
                            }
                        }



                        // NONE IS TRUE
                        if (pagefound != true) {
                            SSL_write(ssl,httpnotfound.c_str(),httpnotfound.length());
                        }
                    }
                } else {
                    if (headerrequest == "POST") {
                        if (bufferstring.length() >= 115) {
                            int timey9000 = 0;
                            int timey9000max = 50;
                            bool completionah = false;
                            int dashesreceived = 0;
                            std::string microstring = "";
                            std::string headerstringpost = "";
                            int micronumber = 4;
                            bool pagefoundpost = false;

                            while(timey9000 <= timey9000max && completionah == false) {
                                micronumber = micronumber + 1;
                                timey9000 = timey9000 + 1;
                                microstring = bufferstring.substr(micronumber, 1);
                                loginfo(microstring, true);
                                if (microstring != "H" && microstring != "/" && microstring != " ") {
                                    if (dashesreceived > 0) {
                                        headerstringpost = headerstringpost + microstring;
                                    }
                                }

                                if (microstring == "H") {
                                    completionah = true;
                                }

                                if (microstring == "/") {
                                    dashesreceived = dashesreceived + 1;
                                }
                            }

                            loginfo("ENOUGH!~" + headerstringpost, true);

                            // LOGINTOACCOUNT
                            if (headerstringpost == "logintoaccount") {
                                loginfo("logintoaccount received", true);
                                pagefoundpost = true;
                                int offset = 0;
                                bool completedlp = false;
                                int timey809 = 0;
                                int timey809max = 100;
                                std::string microswisscode = "";
                                std::string jsonlogin = "";
                                int bufferstringlength = bufferstring.length();

                                while(completedlp == false && timey809 <= timey809max) {
                                    microswisscode = bufferstring.substr(bufferstringlength - offset - 1, 1);
                                    offset = offset + 1;
                                    if (microswisscode == "{") {
                                        jsonlogin = bufferstring.substr(bufferstringlength - offset, bufferstringlength - offset - 1);
                                    } else {
                                        timey809 = timey809 + 1;
                                    }
                                }

                                if (jsonlogin != "") {
                                    // ADD MARIADB CHECK
                                    loginfo(jsonlogin, true);

                                    // GO AHEAD TO ANALYZE JSON AND SEND IT TO MARIADB TO VERIFY
                                    std::string userstringverify = jsonlogin.substr(2,8);
                                    logdebug(userstringverify, true);
                                    if (userstringverify == "username"){
                                        std::string verifyjson = jsonlogin.substr(11,1);
                                        int analyzenumber = 12;
                                        logdebug(verifyjson, true);
                                        if (verifyjson == ":") {
                                            int timering80 = 0;
                                            int timering80max = 80;
                                            bool timering80set = false;
                                            int quotations = 0;
                                            int characternumber = 0;
                                            std::string hellostring = "";
                                            std::string username = "";
                                            while (timering80 <= timering80max && timering80set != true && quotations < 2) {
                                                logdebug(hellostring, true);
                                                hellostring = jsonlogin.substr(analyzenumber, 1);
                                                if (hellostring.find('"') != std::string::npos) {
                                                    quotations = quotations + 1;
                                                    if (quotations > 1) {
                                                        timering80set = true;
                                                    }
                                                } else {
                                                    if (quotations == 1) {
                                                        username = username + hellostring;
                                                    }
                                                }
                                                analyzenumber = analyzenumber + 1;
                                                timering80 = timering80 + 1;
                                            }

                                            hellostring = jsonlogin.substr(analyzenumber, 1);
                                            analyzenumber = analyzenumber + 1;
                                            logdebug(hellostring, true);

                                            if (hellostring == ",") {
                                                // WORK ON VERIFYING PASSWORD
                                                int timering90 = 0;
                                                int timering90max = 64;
                                                bool timering90set = false;
                                                int quotations2 = false;
                                                int characternumber = 0;
                                                analyzenumber = analyzenumber + 11;
                                                std::string password = "";
                                                while (timering90 <= timering90max && timering90set != true && quotations2 < 2) {
                                                    hellostring = jsonlogin.substr(analyzenumber, 1);
                                                    logdebug(hellostring, true);
                                                    if (hellostring.find('"') != std::string::npos) {
                                                        quotations2 = quotations2 + 1;
                                                        if (quotations2 > 1) {
                                                            timering90set = true;
                                                        }
                                                    } else {
                                                        if (quotations2 == 1) {
                                                            password = password + hellostring;
                                                        }
                                                    }
                                                    analyzenumber = analyzenumber + 1;
                                                    timering90 = timering90 + 1;
                                                }

                                                std::cout << "RECEIVED CREDENTIALS user=" << username <<", pass=" << password << ";" << std::endl;
                                                bool verified = mariadbVALIDATE_USER(username, password);
                                                std::cout << "RECEIVED VERIFIED STATUS OF " << verified << std::endl;
                                                if (verified == true) {
                                                    // CREATE SESSION TOKEN AND REDIRECT
                                                    loginfo("SENDING TO ACCOUNT PAGE", true);
                                                    std::string sessiontoken = generateRandomClientKey();
                                                    mariadbINSERT_SESSIONKEY(username, sessiontoken);
                                                    sleep(1);
                                                    int contentlength = 0;
                                                    char doublequote = '"';
                                                    // SEND MODIFIED JSON WITH SUCCESS, CLIENT TOKEN, AND ADDRESS TO FORWARD TO...
                                                    std::string sendpayloadforlength = std::string("{") + doublequote + std::string("state") + doublequote + ":" + doublequote + "ok" + doublequote + "," + doublequote + "token" + doublequote + ":" + doublequote + sessiontoken + doublequote + "," + doublequote + "redirect" + doublequote + ":" + doublequote + "account.html" + doublequote + "}";
                                                    contentlength = sendpayloadforlength.length();
                                                    std::string sendpayloadtoclient = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(contentlength) + "\r\n" + "\r\n" + sendpayloadforlength;
                                                    loginfo("SENDING TO CLIENT...", false);
                                                    int send_res=SSL_write(ssl, sendpayloadtoclient.c_str(), sendpayloadtoclient.length());
                                                    if (send_res <= 0) {
                                                        // Log a critical error message
                                                        logcritical("AN ERROR OCCURRED SENDING SESSION TOKEN!", true);
                                                        // Determine the specific SSL error using SSL_get_error
                                                        int ssl_error_code = SSL_get_error(ssl, send_res);
                                                        switch (ssl_error_code) {
                                                            case SSL_ERROR_WANT_WRITE:
                                                                logcritical("SSL_ERROR_WANT_WRITE: The operation did not complete, try again later.", true);
                                                                break;
                                                            case SSL_ERROR_WANT_READ:
                                                                logcritical("SSL_ERROR_WANT_READ: The operation did not complete, try to read more data.", true);
                                                                break;
                                                            case SSL_ERROR_SYSCALL:
                                                                logcritical("SSL_ERROR_SYSCALL: A system call error occurred.", true);
                                                                break;
                                                            case SSL_ERROR_SSL:
                                                                logcritical("SSL_ERROR_SSL: A failure occurred in the SSL library.", true);
                                                                break;
                                                            default:
                                                                logcritical("Unknown SSL error occurred.", true);
                                                        }
                                                        // Print additional detailed error messages from OpenSSL's error queue
                                                        unsigned long err_code;
                                                        while ((err_code = ERR_get_error()) != 0) {
                                                            char err_buf[256];
                                                            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                                                            logcritical(std::string("SSL Error: ") + err_buf, true); // Log each SSL error
                                                        }
                                                    } else {
                                                        // Log the successful send operation
                                                        loginfo("Sent Payload: " + sendpayloadtoclient, true);
                                                    }
                                                } else {
                                                    int contentlength = 0;
                                                    char doublequote = '"';
                                                    // SEND MODIFIED JSON WITH SUCCESS, CLIENT TOKEN, AND ADDRESS TO FORWARD TO...
                                                    std::string sendpayloadforlength = std::string("{") + doublequote + std::string("state") + doublequote + ":" + doublequote + "wrongpass" + doublequote + "}";
                                                    contentlength = sendpayloadforlength.length();
                                                    std::string sendpayloadtoclient = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(contentlength) + "\r\n" + "\r\n" + sendpayloadforlength;
                                                    loginfo("SENDING TO CLIENT...", true);
                                                    int send_res=SSL_write(ssl, sendpayloadtoclient.c_str(), sendpayloadtoclient.length());
                                                    if (send_res <= 0) {
                                                        // Log a critical error message
                                                        logcritical("AN ERROR OCCURRED SENDING FAIL MESSAGE!", true);
                                                        // Determine the specific SSL error using SSL_get_error
                                                        int ssl_error_code = SSL_get_error(ssl, send_res);
                                                        switch (ssl_error_code) {
                                                            case SSL_ERROR_WANT_WRITE:
                                                                logcritical("SSL_ERROR_WANT_WRITE: The operation did not complete, try again later.", true);
                                                                break;
                                                            case SSL_ERROR_WANT_READ:
                                                                logcritical("SSL_ERROR_WANT_READ: The operation did not complete, try to read more data.", true);
                                                                break;
                                                            case SSL_ERROR_SYSCALL:
                                                                logcritical("SSL_ERROR_SYSCALL: A system call error occurred.", true);
                                                                break;
                                                            case SSL_ERROR_SSL:
                                                                logcritical("SSL_ERROR_SSL: A failure occurred in the SSL library.", true);
                                                                break;
                                                            default:
                                                                logcritical("Unknown SSL error occurred.", true);
                                                        }
                                                        // Print additional detailed error messages from OpenSSL's error queue
                                                        unsigned long err_code;
                                                        while ((err_code = ERR_get_error()) != 0) {
                                                            char err_buf[256];
                                                            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                                                            logcritical(std::string("SSL Error: ") + err_buf, true); // Log each SSL error
                                                        }
                                                    } else {
                                                        // Log the successful send operation
                                                        loginfo("Sent Payload: " + sendpayloadtoclient, true);
                                                    }
                                                }
                                            } else {
                                                SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                            }
                                        } else {
                                            SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                        }
                                    } else {
                                        SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                    }
                                    
                                } else {
                                    SSL_write(ssl,httpforbidden.c_str(),httpforbidden.length());
                                }
                            } 

                            // CREATENEWACCOUNT
                            if (headerstringpost == "createnewaccount") {
                                pagefoundpost = true;
                            }



                            if (pagefoundpost != true) {
                                SSL_write(ssl,httpfail.c_str(),httpfail.length());
                            }
                        } else {
                            logcritical("ERROR OCCURED, dATA NOT LONG ENOUGH", true);
                            SSL_write(ssl,httpfail.c_str(),httpfail.length());
                        }                        
                    } else {
                        SSL_write(ssl,httpfail.c_str(),httpfail.length());
                    }
                }
            } else {
                SSL_write(ssl,httpfail.c_str(),httpfail.length());
            }
        } else {
            // FUTURE TERMINATE COMMAND
            SSL_write(ssl,httpfail.c_str(),httpfail.length());
        }
        
    } 
    close(client_fd);
    return;
    //sleep(600);
    //mariadb_REMOVEPACKETFROMIPADDR(ipaddr);
} 

void handleConnections443(int server_fd) {

    bool port443runningstatus = true;
    int threadnumber = 0;    
    static bool initialized = false;
    char buffer[2048] = {0};
    struct sockaddr_in address, client_addr;
    socklen_t addrlen = sizeof(address);
    SSL *ssl;
    char client_ip[INET_ADDRSTRLEN];
    int checks = 0;
    int allowed = 0;
    socklen_t client_addr_len = sizeof(client_addr);

    if (!initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        initialized = true;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "/certs/server.crt", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "/certs/private.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        logcritical("THE PRIVATE KEY DOES NOT MATCH THE PUBLIC CERTIFICATE!", true);
        SSL_CTX_free(ctx);
        return;
    }

    // TEMP-REMOVE LATER
    bool waiting230 = 0;

    // LOG SERVER STAT INTO MEM
    loginfo("Started!", true);
    statusP443.store(1);

    while (port443runningstatus == true) {
        
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
       
        if (client_fd < 0) {
            if (client_fd == -1) {
                sleep(1);
                if (stopSIGNAL.load() == true) {
                    port443runningstatus = false;
                }
                if (updateSIGNAL.load() == true) {
                    port443runningstatus = false;
                }
            } else {
                loginfo("UNABLE TO ACCEPT HTTPS CONNECTION", true);
                SSL_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
        } else {
            ssl = SSL_new(ctx);
            if (!ssl) {
                ERR_print_errors_fp(stderr);
                close(client_fd);
                SSL_CTX_free(ctx);
                return;
            }
            SSL_set_fd(ssl, client_fd);

            loginfo("heyheyhey", true);

            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::string clientIPADDR = client_ip;
            loginfo("Connection from: " + clientIPADDR, false);
            std::string clientipstd = client_ip;

            // 443 SERVER PROTECTION LAYER 1!
            bool allowed = false;
            auto searchforip = ip443.find(clientipstd);
            if (searchforip != ip443.end()) {
                int logs = searchforip->second;
                std::cout << "RECEIVED VALUE OF " << logs << std::endl;
                if (logs >= 6) {
                    sendtolog("DENIED!", false);
                    ip443.erase(clientipstd);
                    logs = logs + 1;
                    ip443[clientipstd] = logs;
                } else {
                    allowed = true;
                    ip443.erase(clientipstd);
                    logs = logs + 1;
                    ip443[clientipstd] = logs;
                    loginfo("ALLOWED", true);
                }
            } else {
                allowed = true;
                ip443[clientipstd] = 1;
                loginfo("ALLOWED", true);
            }

            if (clientipstd == "172.17.0.1") {
                //loginfo("P443 - RECEIVED LOCALHOST REQUEST, IGNORING...", false);
                //sendtolog(clientipstd);
                return;
            }

            if (allowed == true) {
                // ANTI-CRASH PACKET FLOW CHECK
                if (timer1 == time(NULL)) {
                    packetspam = packetspam + 1;
                    if (packetspam >= 10) {
                        // STOP CONNECTIONS/ENTER BLOCKING STATE
                        waiting230 = true;
                        logwarning("LOCKING HTTPS PORT FOR NOW (PACKET SPAM)", true);
                        timer1 = time(NULL);
                    }
                } else {
                    timer1 = time(NULL);
                    if (packetspam >= 5) {
                        packetspam = packetspam -5;
                        waiting230 = false;
                    } else {
                        packetspam = 0;
                        waiting230 = false;
                    }
                }

                int differenceintime = time(NULL) - timer1;

                if (differenceintime >= 900) {
                    waiting230 = false;
                    logwarning("ALLOWING RESTART OF HTTP PROCESS!", true);
                }

                if (waiting230 == false) { 
                    // SWITCH OF 30 CONSECUTIVE THREADS FOR HTTPS (443)
                    switch (threadnumber) {
                        case 0: {
                            std::thread threadnametrigger00(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger00.detach();
                            break;
                        }
                        case 1: {
                            std::thread threadnametrigger01(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger01.detach();
                            break;
                        }
                        case 2: {
                            std::thread threadnametrigger02(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger02.detach();
                            break;
                        }
                        case 3: {
                            std::thread threadnametrigger03(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger03.detach();
                            break;
                        }
                        case 4: {
                            std::thread threadnametrigger04(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger04.detach();
                            break;
                        }
                        case 5: {
                            std::thread threadnametrigger05(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger05.detach();
                            break;
                        }
                        case 6: {
                            std::thread threadnametrigger06(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger06.detach();
                            break;
                        }
                        case 7: {
                            std::thread threadnametrigger07(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger07.detach();
                            break;
                        }
                        case 8: {
                            std::thread threadnametrigger08(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger08.detach();
                            break;
                        }
                        case 9: {
                            std::thread threadnametrigger09(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger09.detach();
                            break;
                        }
                        case 10: {
                            std::thread threadnametrigger10(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger10.detach();
                            break;
                        }
                        case 11: {
                            std::thread threadnametrigger11(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger11.detach();
                            break;
                        }
                        case 12: {
                            std::thread threadnametrigger12(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger12.detach();
                            break;
                        }
                        case 13: {
                            std::thread threadnametrigger13(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger13.detach();
                            break;
                        }
                        case 14: {
                            std::thread threadnametrigger14(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger14.detach();
                            break;
                        }
                        case 15: {
                            std::thread threadnametrigger15(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger15.detach();
                            break;
                        }
                        case 16: {
                            std::thread threadnametrigger16(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger16.detach();
                            break;
                        }
                        case 17: {
                            std::thread threadnametrigger17(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger17.detach();
                            break;
                        }
                        case 18: {
                            std::thread threadnametrigger18(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger18.detach();
                            break;
                        }
                        case 19: {
                            std::thread threadnametrigger19(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger19.detach();
                            break;
                        }
                        case 20: {
                            std::thread threadnametrigger20(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger20.detach();
                            break;
                        }
                        case 21: {
                            std::thread threadnametrigger21(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger21.detach();
                            break;
                        }
                        case 22: {
                            std::thread threadnametrigger22(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger22.detach();
                            break;
                        }
                        case 23: {
                            std::thread threadnametrigger23(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger23.detach();
                            break;
                        }
                        case 24: {
                            std::thread threadnametrigger24(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger24.detach();
                            break;
                        }
                        case 25: {
                            std::thread threadnametrigger25(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger25.detach();
                            break;
                        }
                        case 26: {
                            std::thread threadnametrigger26(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger26.detach();
                            break;
                        }
                        case 27: {
                            std::thread threadnametrigger27(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger27.detach();
                            break;
                        }
                        case 28: {
                            std::thread threadnametrigger28(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger28.detach();
                            break;
                        }
                        case 29: {
                            std::thread threadnametrigger29(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger29.detach();
                            break;
                        }
                        case 30: {
                            std::thread threadnametrigger30(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger30.detach();
                            break;
                        }
                        case 31: {
                            std::thread threadnametrigger31(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger31.detach();
                            break;
                        }
                        case 32: {
                            std::thread threadnametrigger32(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger32.detach();
                            break;
                        }
                        case 33: {
                            std::thread threadnametrigger33(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger33.detach();
                            break;
                        }
                        case 34: {
                            std::thread threadnametrigger34(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger34.detach();
                            break;
                        }
                        case 35: {
                            std::thread threadnametrigger35(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger35.detach();
                            break;
                        }
                        case 36: {
                            std::thread threadnametrigger36(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger36.detach();
                            break;
                        }
                        case 37: {
                            std::thread threadnametrigger37(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger37.detach();
                            break;
                        }
                        case 38: {
                            std::thread threadnametrigger38(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger38.detach();
                            break;
                        }
                        case 39: {
                            std::thread threadnametrigger39(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger39.detach();
                            break;
                        }
                        case 40: {
                            std::thread threadnametrigger40(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger40.detach();
                            break;
                        }
                        case 41: {
                            std::thread threadnametrigger41(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger41.detach();
                            break;
                        }
                        case 42: {
                            std::thread threadnametrigger42(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger42.detach();
                            break;
                        }
                        case 43: {
                            std::thread threadnametrigger43(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger43.detach();
                            break;
                        }
                        case 44: {
                            std::thread threadnametrigger44(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger44.detach();
                            break;
                        }
                        case 45: {
                            std::thread threadnametrigger45(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger45.detach();
                            break;
                        }
                        case 46: {
                            std::thread threadnametrigger46(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger46.detach();
                            break;
                        }
                        case 47: {
                            std::thread threadnametrigger47(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger47.detach();
                            break;
                        }
                        case 48: {
                            std::thread threadnametrigger48(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger48.detach();
                            break;
                        }
                        case 49: {
                            std::thread threadnametrigger49(httpsconnectionthread, ssl, client_ip, client_fd, client_addr);
                            threadnametrigger49.detach();
                            break;
                        }
                    }
                    if (threadnumber == 49) {
                        threadnumber = 0;
                    } else {
                        threadnumber = threadnumber + 1;
                    }
                }
            }
        }   
    }

    // SEND TO SERVER MEM
    loginfo("P443 - Stopped...", true);
    statusP443.store(0);
    close(server_fd);
    sleep(1);
    return;
}
