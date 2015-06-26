#include <jni.h>
#include <string.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <errno.h>

#define DEBUG_TAG "Softenc"

void logcatError(const char *msg)
{
    __android_log_print(ANDROID_LOG_ERROR, DEBUG_TAG, "NDK:LC:ERR: [%s], Errno: %i", msg, errno);
}

void logcatDebug(const char *msg)
{
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NDK:LC:DBG: [%s]", msg);
}

// source: http://www.linuxhowtos.org/C_C++/socket.htm
int Java_de_unikl_cs_disco_softenc_SoftencActivity_sendUrgent(JNIEnv * env, jobject this,
        jstring jurl, int portno, jstring jdata, jboolean jSetUrgentFlag)
{
    jboolean isCopy;
    const char * url = (*env)->GetStringUTFChars(env, jurl, &isCopy);
    const char * data = (*env)->GetStringUTFChars(env, jdata, &isCopy);
    const int flagname = SO_OOBINLINE;
    //const int flagname = 1337;

    int sockfd , sockopterr, socketOptionEnabled, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];
    logcatDebug("Opening Socket");
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        logcatError("ERROR opening socket");
        return -1;
    }

    if (jSetUrgentFlag)
    {
    socketOptionEnabled = 1;
    }
    else
    {
    socketOptionEnabled = 0;
    }
    sockopterr = setsockopt(sockfd, SOL_SOCKET, flagname, (void *)&socketOptionEnabled, sizeof(socketOptionEnabled));
    if (sockopterr < 0)
    {
        logcatError("ERROR setting sockopt");
        return -2;
    }

    server = gethostbyname(url);
    if (server == NULL)
    {
        logcatError("ERROR Host not found");
        return -3;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
    {
        logcatError("ERROR connecting");
        return -4;
    }
    n = write(sockfd,data,strlen(data));
    if (n < 0)
    {
         logcatError("ERROR writing to socket");
    }

    close(sockfd);

    (*env)->ReleaseStringUTFChars(env, jurl, url);
    (*env)->ReleaseStringUTFChars(env, jdata, data);
    return 0;
}




