/*

Author: Espen Graarud <espengra@cs.ucsb.edu>
Course: CS 176B
Homework 2: mftp
Submitted: 2.11.2010

Online resources/examples used:
- http://math.asu.edu/~eric/mat420/gnu_libc/Getopt-Long-Option-Example.html#Getopt-Long-Option-Example
- http://beej.us/guide/bgnet/output/html/multipage/syscalls.html
- ++

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <sys/types.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#define MAXBUFLEN 5000

extern char *strndup (__const char *__string, size_t __n);




void Usage() {
  printf("-h or --help     : Shows this help\n");
  printf("-v or --version  : Displays the current version number\n");
  printf("-f or --file     : Specify file to download\n");
  printf("-s or --server   : Specify server name\n");
  printf("-p or --port     : Default port is 21\n");
  printf("-n or --username : Default username is 'anonymous'\n");
  printf("-P or --password : Defalt password is 'user@localhost.localnet'\n");
  printf("-a or --active   : Default mode is 'passive'\n");
  printf("-m or --mode     : Specifies ASCII or binary, default: binary)\n");
  printf("-l or --log      : Saves the log to a file\n");
}




void Connection(char *server, int inputPort, char *username, char *password, int active, int ascii, char *filename, int log, char *logName) {
  char recvBuf[MAXBUFLEN] = {0};
  int status, status2, status3, i, j, k, code, dataPort, commas, isset = 0;
  int socketControl, socketData, socketActive = 0;
  struct addrinfo hints, *res;
  struct addrinfo hintsActive;
  struct addrinfo *resActive;
  struct sockaddr_storage their_addr;
  socklen_t addr_size;
  addr_size = sizeof their_addr;
  char *codeTmp;
  char user[64], pass[64], mode[16], xferMode[16], port[5], file[64] = {0};
  char prePort[5], postPort[5], ipAndPort[20] = {0};

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char xPort[10];
  sprintf(xPort, "%d", inputPort);

  if( (status = getaddrinfo(server, xPort, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    exit(1);
  }

  socketControl = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  connect(socketControl, res->ai_addr, res->ai_addrlen);

  if(strcmp(logName, "-") != 0) {
    freopen(logName, "w", stdout);
  }

  while( (recv(socketControl, &recvBuf, MAXBUFLEN, 0)) > 0) {
    codeTmp = strndup(recvBuf, 3);
    code = atoi(codeTmp);

    if(log) {
      printf("S->C: ");
      for(i=0; i<MAXBUFLEN; i++) {
        printf("%c", recvBuf[i]);
      }
    }


    switch(code) {
      case 220:
        strcpy(user, "USER ");
        strcat(user, username);
        strcat(user, "\n");
        send(socketControl, &user, strlen(user), 0);
        if(log) {
          printf("C->S: ");
          printf("%s", user);
        }
        break;

      case 331:
        strcpy(pass, "PASS ");
        strcat(pass, password);
        strcat(pass, "\n");
        send(socketControl, &pass, strlen(pass), 0);
        if(log) {
          printf("C->S: ");
          printf("%s", pass);
        }
        break;

      case 230:
        for(i=0; i<MAXBUFLEN; i++) {
          if(recvBuf[i]=='2' && recvBuf[i+1]=='3' && recvBuf[i+2]=='0' && recvBuf[i+3] ==' ') {
            if(active == 0) {
              strcpy(mode, "PASV\n");
              send(socketControl, &mode, strlen(mode), 0);
              if(log) {
                printf("C->S: ");
                printf("%s", mode);
              }
            } 
            else {
              int sfd;
              struct ifreq ifr;
              struct sockaddr_in *sinx = (struct sockaddr_in *) &ifr.ifr_addr;
              memset(&ifr, 0, sizeof ifr);
              if (0 > (sfd = socket(AF_INET, SOCK_STREAM, 0))) {
                perror("socket()");
                exit(1);
              }
              strcpy(ifr.ifr_name, "eth0");
              sinx->sin_family = AF_INET;
              char myIP[16];
              int myPort;
              if (0 == ioctl(sfd, SIOCGIFADDR, &ifr)) {
                sprintf(myIP, "%s", inet_ntoa(sinx->sin_addr));
              }
              char *dotPtr;
              for(i=0; i<3; i++) {
                dotPtr = strrchr(myIP, '.');
                *(char *)dotPtr = ',';
              }

              struct sockaddr_in sa;
              int sa_len;
              sa_len = sizeof(sa);
              if (getsockname(socketControl, (struct sockaddr_in *) &sa, (socklen_t *)&sa_len) == -1) {
                perror("getsockname() failed");
              }
              myPort = (int) ntohs(sa.sin_port);
              myPort++;
              int tmp = myPort/256;
              sprintf(prePort, "%d", tmp);
              tmp = myPort % 256;
              sprintf(postPort, "%d", tmp);
              sprintf(ipAndPort, "%s,%s,%s", myIP, prePort, postPort);
              char portChar[10];
              sprintf(portChar, "%d", myPort);

              memset(&hintsActive, 0, sizeof hintsActive);
              hintsActive.ai_family = AF_UNSPEC;
              hintsActive.ai_socktype = SOCK_STREAM;
              hintsActive.ai_flags = AI_PASSIVE;

              getaddrinfo(NULL, portChar, &hintsActive, &resActive);
              socketActive = socket(resActive->ai_family, resActive->ai_socktype, resActive->ai_protocol);
              bind(socketActive, resActive->ai_addr, resActive->ai_addrlen);
              listen(socketActive, 5);
              char sendIpPort[30] = {0};
              sprintf(sendIpPort, "PORT %s\n", ipAndPort);
              send(socketControl, &sendIpPort, strlen(sendIpPort), 0);
              if(log) {
                printf("C->S: ");
                printf("%s", sendIpPort);
              }
            }
            break;
          }
        }
        break;

      case 227:
        j = 0;
        k = 0;
        commas = 0;
        for(i=0; i<sizeof recvBuf; i++) {
          if(recvBuf[i]==')') {
            break;
          } else if(recvBuf[i]==',') {
            commas++;
          } else if(commas==4) {
            prePort[j] = recvBuf[i];
            j++;
          } else if(commas==5) {
            postPort[k] = recvBuf[i];
            k++;
          }
        }
        dataPort = atoi(prePort);
        dataPort = dataPort*256;
        dataPort = dataPort + atoi(postPort);
        sprintf(port, "%d", dataPort);

        status2 = getaddrinfo(server, port, &hints, &res);
        socketData = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        connect(socketData, res->ai_addr, res->ai_addrlen);

        if(ascii == 0) {
          strcpy(xferMode, "TYPE I\n");
          send(socketControl, &xferMode, strlen(xferMode), 0);
          if(log) {
            printf("C->S: ");
            printf("%s", xferMode);
          }
        } else {
          strcpy(xferMode, "TYPE A\n");
          send(socketControl, &xferMode, strlen(xferMode), 0);
          if(log) {
            printf("C->S: ");
            printf("%s", xferMode);
          }
        }
        break;

      case 200:
        if ( (isset == 0) && (active == 1) ) {
          isset = 1;
          if(ascii == 0) {
            strcpy(xferMode, "TYPE I\n");
            send(socketControl, &xferMode, strlen(xferMode), 0);
            if(log) {
              printf("C->S: ");
              printf("%s", xferMode);
            }
          } else {
            strcpy(xferMode, "TYPE A\n");
            send(socketControl, &xferMode, strlen(xferMode), 0);
            if(log) {
              printf("C->S: ");
              printf("%s", xferMode);
            }
          }
        }
        else {
          strcpy(file, "RETR ");
          strcat(file, filename);
          strcat(file, "\n");
          send(socketControl, &file, strlen(file), 0);
          if(log) {
            printf("C->S: ");
            printf("%s", file);
          }
        }
        break;

      case 150:
        if(active) {
          socketData = accept(socketActive, (struct sockaddr *)&their_addr, &addr_size);
        }
        for(i=0; i<MAXBUFLEN; i++) {
          recvBuf[i] = 0;
        }

        char saveFile[64];
        if(strstr(filename, "/")!=NULL) {
          char *slashPtr = strrchr(filename, '/');
          strcpy(saveFile, slashPtr+1);
        } else {
          strcpy(saveFile, filename);
        }

        FILE *fp;
        fp = fopen(saveFile, "wb");

        int receive = 1;
        while( receive > 0 ) {
          receive = recv(socketData, &recvBuf, MAXBUFLEN-1, 0);
          recvBuf[receive] = '\0';
          fwrite(recvBuf, 1, receive, fp);

          for(i=0; i<MAXBUFLEN; i++) {
            recvBuf[i] = 0;
          }
        }
        fclose(fp);
        close(socketData);
        break;

      case 226:
        close(socketControl);
        fclose(stdout);
        break;

      case 421:
//         421 No transfer timeout (600 seconds): closing control connection
        fclose(stdout);
        exit(7);

      case 501:
//         501 Invalid number of arguments
        fclose(stdout);
        exit(6);
        
      case 530:
//         530 Login incorrect
        fclose(stdout);
        exit(2);

      case 550:
//         550 No such file or directory
        fclose(stdout);
        exit(3);

      default:
        fclose(stdout);
        exit(7);
    }
    for(i=0; i<MAXBUFLEN; i++) {
      recvBuf[i] = 0;
    }
  }
  fclose(stdout);
  return;
}









int main(int argc, char *argv[]) {
  extern char *optarg;
  extern int optind, optopt, opterr;
  opterr = 0;
  int options;
  char *version = "0.1";
  char *filename;
  char *server;
  int port = 21;
  char *username = "anonymous";
  char *password = "user@localhost.localnet";
  int active = 0;
  int ascii = 0;
  int log = 0;
  char *logName = "-";

  if(argc == 1){
    Usage();
    exit(4);
  }

  static struct option long_options[] = {
    { "help"      , 0, 0, 'h' },
    { "version"   , 0, 0, 'v' },
    { "file"      , 1, 0, 'f' },
    { "server"    , 1, 0, 's' },
    { "port"      , 1, 0, 'p' },
    { "username"  , 1, 0, 'n' },
    { "password"  , 1, 0, 'P' },
    { "active"    , 0, 0, 'a' },
    { "mode"      , 1, 0, 'm' },
    { "log"       , 1, 0, 'l' },
  };

  while( (options = getopt_long(argc, argv, "hvf:s:p:n:P:am:l:", long_options, NULL)) != -1) {
    switch(options) {
      case 'h':
        Usage();
        exit(0);
      case 'v':
        printf("APPLICATION  : mftp\n");
        printf("VERSION      : %s\n", version);
        printf("AUTHOR NAME  : Espen Graarud\n");
        printf("AUTHOR EMAIL : espengra@cs.ucsb.edu\n");
        exit(0);
      case 'f':
        filename = optarg;
        break;
      case 's':
        server = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'n':
        username = optarg;
        break;
      case 'P':
        password = optarg;
        break;
      case 'a':
        active = 1;
        break;
      case 'm':
        if (strcmp(optarg, "ASCII") == 0){
          ascii = 1;
        } else {
          ascii = 0;
        }
        break;
      case 'l':
        log = 1;
        logName = optarg;
        break;
      default:
        Usage();
        exit(4);
    }
  }

  Connection(server, port, username, password, active, ascii, filename, log, logName);
  exit(0);
}

