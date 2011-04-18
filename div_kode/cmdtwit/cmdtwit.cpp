/*

Author    : Espen Graarud <espengra@cs.ucsb.edu>
Course    : CS 176B
Homework 3: cmdtwit
Submitted : 3.15.2010

Online resources/examples used:
- http://www.linuxhowtos.org/C_C++/socket.htm
- http://apiwiki.twitter.com/Twitter-API-Documentation
- http://www.cs.cf.ac.uk/Dave/C/node24.html

*/

#include "base64.h"
#include <iostream>
#include <cstdlib>
#include <getopt.h>
#include <vector>
#include <sstream>
#include <string>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>

using namespace std;

#define MAXBUFLEN 5000

void Run();

void Usage();
void Version();
void GetStatus();
void UpdateStatus();
void TimeLine();
void Follow();
void UnFollow();
void ListFollowing();
void ListFollowers();
void Stream();
void Exit();

void ParseCmdInput();
void Connect();
void ConnectToStream();
char *Authenticate();
void CheckRemainingApiCalls();
void CheckReturnCode(string msg);
string GetFriendIDs();

int i, j;
int options;
int prePosts;
int countPosts;
int pages;
int sockfd;
int auth;
int stream;

char remainingApiCalls[256] = {0};
char toSend[256] = {0};
char recvBuf[MAXBUFLEN] = {0};
char getStatus[256] = {0};

string version;
string username;
string follow;
string unfollow;
string password;
string status;
string line;
string numTweetsStr;
string list;
string authString;
string api;

bool interactive, uIsSet, pIsSet, setStatusBool, getStatusBool, countTimeLineBool, streamMode = false;

vector<string> commands;

extern char *optarg;
extern int optind, optopt, opterr;

struct addrinfo hints, *res;

void sighandler(int sig) {
	if(sig==2 && streamMode) {
		streamMode = false;
	} else {
		cout << "\nGood Bye!\n";
		exit(0);
	}
}

int main(int argc, char *argv[]) {
	signal(SIGINT, &sighandler);
	version = "0.1";
	opterr = 0;
	interactive = true;
	auth = -1;

	static struct option long_options[] = {
		{ "help"          , 0, 0, 'h' },
		{ "version"       , 0, 0, 'v' },
		{ "username"      , 1, 0, 'u' },
		{ "password"      , 1, 0, 'p' },
		{ "setstatus"     , 1, 0, 's' },
		{ "getstatus"     , 1, 0, 'g' },
		{ "counttimeline" , 1, 0, 'c' },
	};

	while( (options = getopt_long(argc, argv, "hvu:p:s:g:c:", long_options, NULL)) != -1) {
		switch(options) {
			case 'h':
				Usage();
				exit(0);
			case 'v':
				Version();
				exit(0);
			case 'u':
				if(username.empty()) {
					auth++;
				}
				username = optarg;
				break;
			case 'p':
				if(password.empty()) {
					auth++;
				}
				password = optarg;
				break;
			case 's':
				status = optarg;
				setStatusBool = true;
				break;
			case 'g':
				strncpy(getStatus, optarg, 63);
				getStatusBool = true;
				break;
			case 'c':
				countPosts = atoi(optarg);
				countTimeLineBool = true;
				break;
			default:
				Usage();
				exit(4);
		}
	}

	if(setStatusBool) {
		if(auth=1){
			UpdateStatus();
			exit(0);
		} else {
			cout << "\nYou need to authenticate yourself before you update your status!\n\n";
			exit(3);
		}
	} else if(getStatusBool) {
		GetStatus();
		exit(0);
	} else if(countTimeLineBool) {
		if(auth=1){
			TimeLine();
			exit(0);
		} else {
			cout << "\nYou need to authenticate yourself to access your timeline\n\n";
			exit(3);
		}
	}

	Run();

	exit(0);
}

void Usage() {
	cout << endl;
	cout << "-h or --help          : Shows this help\n";
	cout << "-v or --version       : Displays the current version number\n";
	cout << "-u or --username      : Specify the username\n";
	cout << "-p or --password      : Specify the password\n";
	cout << "-s or --setstatus     : Update status\n";
	cout << "-g or --getstatus     : Get last status from user\n";
	cout << "-c or --counttimeline : Get postcount from user\n";
	cout << endl;
}

void Version() {
	cout << endl;
	cout << "APPLICATION  : cmdtwit\n";
    cout << "VERSION      : " << version << endl;
    cout << "AUTHOR NAME  : Espen Graarud\n";
    cout << "AUTHOR EMAIL : espengra@cs.ucsb.edu\n";
    cout << endl;
}

void Run() {
	while(true) {
		cout << "\n>> ";
		getline(cin, line, '\n');
		ParseCmdInput();
	}
}

void ParseCmdInput() {
	istringstream iss(line, istringstream::in);
	commands.erase(commands.begin(),commands.begin()+commands.size());
	string tmp;
	while(iss >> tmp) {
		commands.push_back(tmp);
	}
	i = 0;
	while(i<commands.size()) {
//		cout << "commands.size() = " << commands.size() << endl;
		if ( (commands.at(i) == "login") && (i+1 <= commands.size()-1) ) {
			if(username.empty()) {
				auth++;
			}
			username = commands.at(i+1);
			i++;
			cout << "You have set your username to " << username << endl;
		}
		else if( (commands.at(i) == "password") && (i+1 <= commands.size()-1) ) {
			if(password.empty()) {
				auth++;
			}
			password = commands.at(i+1);
			i++;
			cout << "You have set a password\n";
		}
		else if( commands.at(i) == "logout" ) {
			username.erase(0, username.size());
			password.erase(0, password.size());
			auth = -1;
			cout << "You have successfully logged out\n";
		}
		else if( (commands.at(i) == "tweet") && (i+1 <= commands.size()-1) ) {
//			status = commands.at(i+1);
//			i++;
			size_t startPos = line.find("//")+2;
			size_t endPos = line.rfind("//");
			if(startPos == string::npos || endPos == string::npos || startPos-2 == endPos) {
				cout << "You need to prepend and append // to your tweet!\n";
			} else {
				status.assign(line, startPos, endPos-startPos);
			}
			i = commands.size()-1;
			UpdateStatus();
		}
		else if( (commands.at(i) == "list") && (i+1 <= commands.size()-1) ) {
			list = commands.at(i+1);
			if(list.compare("up") == 0) {
				ListFollowing();
			} else if(list.compare("down") == 0) {
				ListFollowers();
			} else {
				cout << "\nWrong input. Use 'list up' or 'list down'.\n";
			}
			i++;
		}
		else if( (commands.at(i) == "follow") && (i+1 <= commands.size()-1) ) {
			follow = commands.at(i+1);
			i++;
			Follow();
		}
		else if( (commands.at(i) == "unfollow") && (i+1 <= commands.size()-1) ) {
			unfollow = commands.at(i+1);
			i++;
			UnFollow();
		}
		else if( (commands.at(i) == "display") && (i+2 <= commands.size()-1) && (commands.at(i+1) == "tweets") ) {
			numTweetsStr = commands.at(i+2);
			if(numTweetsStr.find("-") == string::npos) {
				prePosts = 0;
				countPosts = atoi(numTweetsStr.c_str());
			} else {
				size_t dash;
				dash = numTweetsStr.find("-");
				prePosts = atoi(numTweetsStr.substr(0, dash).c_str());
				countPosts = atoi(numTweetsStr.substr(dash+1).c_str());
			}
			i += 2;
			TimeLine();
		}
		else if( (commands.at(i) == "stream") && (i+1 <= commands.size()-1) ) {
			stream = atoi(commands.at(i+1).c_str());
			i++;
			Stream();
		}
		else if( commands.at(i) == "exit" ) {
			cout << "Good Bye!\n";
			exit(0);
		}
		i++;
	}
}

void Connect() {
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo("www.twitter.com", "80", &hints, &res);
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		cout << "Error: Could not connecto to Twitter\n";
		exit(1);
	}
}

void ConnectToStream() {
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo("stream.twitter.com", "80", &hints, &res);
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		cout << "Error: Could not connecto to Twitter\n";
		exit(1);
	}
}

char *Authenticate() {
	if(auth==1) {
		string authenticator = username;
		authenticator = authenticator + ":";
		authenticator = authenticator + password;
		string encodedAuth = base64_encode(reinterpret_cast<const unsigned char*>(authenticator.c_str()), authenticator.length());
		authString = "Authorization: Basic " + encodedAuth + "\n";
		static char returnChar[256] = {0};
		sprintf(returnChar, "%s", reinterpret_cast<const unsigned char*>(authString.c_str()), authString.length());
		return returnChar;
	} else {
		static char returnChar[256] = {0};
		sprintf(returnChar, "\n");
		return returnChar;
	}
}



void CheckRemainingApiCalls() {
	Connect();

	sprintf(toSend, "GET /account/rate_limit_status.xml HTTP/1.1\nHost: www.twitter.com\n%s\n", Authenticate());
	toSend[strlen(toSend)] = '\0';

	write(sockfd,&toSend,strlen(toSend));
	string received;
	while(read(sockfd, recvBuf, MAXBUFLEN) > 0) {
		received += recvBuf;
		memset(recvBuf, 0, sizeof recvBuf);
	}

	int startPos, endPos = 0;
	startPos = received.find("<remaining-hits type=\"integer\">")+31;
	endPos = received.find("</remaining-hits>");
	api.assign(received, startPos, endPos-startPos);

	if(atoi(api.c_str()) < 30) {
		cout << "Less than 30 API calls remaining. Closing application with code 7\n";
		exit(7);
	}
}

void GetStatus() {
	CheckRemainingApiCalls();
	Connect();

	sprintf(toSend, "GET /users/show.xml?screen_name=%s HTTP/1.1\nHost: www.twitter.com\n%s\n", getStatus, Authenticate());
	write(sockfd,&toSend,strlen(toSend));
	string received;
	char test[8] = {0};
	do {
		i = read(sockfd, recvBuf, MAXBUFLEN);
		recvBuf[i] = '\0';
		received += recvBuf;

		if(received.find("HTTP/1.1 404 Not Found") != string::npos ) {
			cout << "User not found. Exiting application with code 4\n";
			exit(4);
		}

		if(received.find("<statuses_count>0</statuses_count>") != string::npos ) {
			cout << "The user has no statuses. Exiting application with code 6\n";
			exit(6);
		}

		memset(recvBuf, 0, sizeof recvBuf);
	}
	while(received.find("</user>") == string::npos);

	if(received.find("<status>") == string::npos) {
		cout << endl << "User not authenticated. Exiting application with code 3\n";
		exit(3);
	}

	size_t startPos, endPos = 0;
	string statusString;
	startPos = received.find("<text>")+6;
	endPos = received.find("</text>");
	statusString = received.substr(startPos, endPos-startPos);
	cout << endl << statusString << endl << endl;

}

void UpdateStatus() {
	if(status.length()>140) {
		cout << "\nStatus message too long (MAX 140 chars). Exiting application with code 6\n";
		exit(6);
	}

	Connect();

	sprintf(toSend, "POST /statuses/update.xml HTTP/1.1\nHost: www.twitter.com\n%sContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\nstatus=%s", Authenticate(), status.length()+7, reinterpret_cast<const unsigned char*>(status.c_str()), status.length());
	write(sockfd,&toSend,strlen(toSend));

	string received;
	while( read(sockfd, recvBuf, MAXBUFLEN) > 0) {
		received += recvBuf;
		memset(recvBuf, 0, sizeof recvBuf);
	}
	CheckReturnCode(received);
	cout << "Status successfully updated!\n";
}

void CheckReturnCode(string msg) {
	if(msg.find("200 OK") != string::npos) {
		return;
	} else if(msg.find("401 Unauthorized") != string::npos) {
		cout << "Authentication Failed! Exiting application with code 2\n";
		exit(2);
	} else if(msg.find("403 Forbidden") != string::npos) {
		string errorStart = "<error>";
		string errorEnd = "</error>";
		size_t foundStart, foundEnd = 0;
		foundStart = msg.find(errorStart)+7;
		foundEnd = msg.find(errorEnd);
		string error_msg;
		error_msg.assign(msg, foundStart, foundEnd-foundStart);
		cout << "Error: " << error_msg << "\nExiting application with code 7\n";
		exit(7);
	}else if(msg.find("<error>Not found</error>") != string::npos) {
		cout << "Authentication Failed! Exiting application with code 2\n";
		exit(2);
	} else {
		string errorStart = "<error>";
		string errorEnd = "</error>";
		size_t foundStart, foundEnd = 0;
		foundStart = msg.find(errorStart)+7;
		foundEnd = msg.find(errorEnd);
		string error_msg;
		error_msg.assign(msg, foundStart, foundEnd-foundStart);
		cout << "Error: " << error_msg << "\nExiting application with code 7\n";
		exit(7);

	}

}

void TimeLine() {
	string received;
	string tweet, author;
	string tweetStart = "<text>";
	string tweetEnd = "</text>";
	string authorStart = "<screen_name>";
	string authorEnd = "</screen_name>";
	int foundStart = 0;
	int foundEnd = 0;

	if(countPosts>3200) {
		cout << "Threshold of 3200 exceeded!\n";
	}else {
		if(countPosts>200) {
			if(countPosts%200 == 0) {
				pages = countPosts/200;
			} else {
				pages = countPosts/200+1;
			}
			for(i=1; i<=pages; i++) {
				CheckRemainingApiCalls();
				Connect();
				sprintf(toSend, "GET /statuses/home_timeline.xml?page=%d&count=200 HTTP/1.1\nHost: www.twitter.com\n%s\n", i, Authenticate());
				write(sockfd,&toSend,strlen(toSend));
				while (read(sockfd, recvBuf, MAXBUFLEN)>0) {
					received += recvBuf;
					memset(recvBuf, 0, sizeof recvBuf);
				}
			}
		} else {
			CheckRemainingApiCalls();
			Connect();
			sprintf(toSend, "GET /statuses/home_timeline.xml?count=%d HTTP/1.1\nHost: www.twitter.com\n%s\n", countPosts, Authenticate());
			write(sockfd,&toSend,strlen(toSend));
			while (read(sockfd, recvBuf, MAXBUFLEN)>0) {
				received += recvBuf;
				memset(recvBuf, 0, sizeof recvBuf);
			}
		}
		for(i=0; i<prePosts; i++) {
			foundStart = received.find(authorStart)+13;
			if (foundStart == string::npos) {
				break;
			}
			foundEnd = received.find(authorEnd);
			if (foundEnd == string::npos) {
				break;
			}
			received.assign(received, foundEnd, received.length()-foundEnd);
		}
		for(i=prePosts; i<countPosts; i++) {

			foundStart = received.find(tweetStart)+6;
			if (foundStart == string::npos) {
				break;
			}
			foundEnd = received.find(tweetEnd);
			if (foundEnd == string::npos) {
				break;
			}
			tweet.assign(received, foundStart, foundEnd-foundStart);
			received.assign(received, foundEnd, received.length()-foundEnd);

			foundStart = received.find(authorStart)+13;
			if (foundStart == string::npos) {
				break;
			}
			foundEnd = received.find(authorEnd);
			if (foundEnd == string::npos) {
				break;
			}
			author.assign(received, foundStart, foundEnd-foundStart);
			received.assign(received, foundEnd, received.length()-foundEnd);
			cout << "\n@" << author << endl << tweet << endl;
		}
	}
}


void ListFollowing() {
	CheckRemainingApiCalls();

	string received;
	size_t startPos, endPos, startCursor, endCursor = 0;
	string screen_name, cursor;
	i = 1;
	cursor = "-1";
	do {
		startPos = 0;
		endPos = 0;
		startCursor = 0;
		endCursor = 0;

		Connect();

		if(atoi(api.c_str()) <= i+30) {
			cout << "Less than 30 API calls remaining. Closing application with code 7\n";
			exit(7);
		}
		sprintf(toSend, "GET /statuses/friends.xml?cursor=%s HTTP/1.1\nHost: www.twitter.com\n%s\n", cursor.c_str(), Authenticate());
		write(sockfd,&toSend,strlen(toSend));

		do {
			read(sockfd, recvBuf, MAXBUFLEN);
			received += recvBuf;
			memset(recvBuf, 0, sizeof recvBuf);
		} while(received.find("</users_list>") == string::npos);

		while((startPos != string::npos) && (startPos != received.rfind("<screen_name>"))) {
			startPos = received.find("<screen_name>", endPos);
			endPos = received.find("</screen_name>", startPos);
			screen_name.assign(received, startPos+13, endPos-startPos-13);
			cout << screen_name << endl;
		}

		startCursor = received.rfind("<next_cursor>");
		endCursor = received.rfind("</next_cursor>");
		cursor.assign(received, startCursor+13, endCursor-startCursor-13);
		received = "";

		i++;

	} while(cursor.compare("0") != 0);
}

void ListFollowers() {
	CheckRemainingApiCalls();

	string received;
	size_t startPos, endPos, startCursor, endCursor = 0;
	string screen_name, cursor;
	i = 1;
	cursor = "-1";
	do {
		startPos = 0;
		endPos = 0;
		startCursor = 0;
		endCursor = 0;

		Connect();

		if(atoi(api.c_str()) <= i+30) {
			cout << "Less than 30 API calls remaining. Closing application with code 7\n";
			exit(7);
		}
		sprintf(toSend, "GET /statuses/followers.xml?cursor=%s HTTP/1.1\nHost: www.twitter.com\n%s\n", cursor.c_str(), Authenticate());
		write(sockfd,&toSend,strlen(toSend));

		do {
			read(sockfd, recvBuf, MAXBUFLEN);
			received += recvBuf;
			memset(recvBuf, 0, sizeof recvBuf);
		} while(received.find("</users_list>") == string::npos);

		while((startPos != string::npos) && (startPos != received.rfind("<screen_name>"))) {
			startPos = received.find("<screen_name>", endPos);
			endPos = received.find("</screen_name>", startPos);
			screen_name.assign(received, startPos+13, endPos-startPos-13);
			cout << screen_name << endl;
		}

		startCursor = received.rfind("<next_cursor>");
		endCursor = received.rfind("</next_cursor>");
		cursor.assign(received, startCursor+13, endCursor-startCursor-13);
		received = "";

		i++;

	} while(cursor.compare("0") != 0);
}

void Follow() {
	Connect();

	sprintf(toSend, "POST /friendships/create.xml HTTP/1.1\nHost: www.twitter.com\n%sContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\nscreen_name=%s", Authenticate(), follow.length()+12, follow.c_str());
	write(sockfd,&toSend,strlen(toSend));

	string received;
	while(read(sockfd, recvBuf, MAXBUFLEN)>0) {
		received += recvBuf;
		memset(recvBuf, 0, sizeof recvBuf);
	}
	CheckReturnCode(received);
	cout << "You successfully followed " << follow << "!\n";
}

void UnFollow() {
	Connect();

	sprintf(toSend, "POST /friendships/destroy.xml HTTP/1.1\nHost: www.twitter.com\n%sContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\nscreen_name=%s", Authenticate(), unfollow.length()+12, unfollow.c_str());
	write(sockfd,&toSend,strlen(toSend));

	string received;
	while(read(sockfd, recvBuf, MAXBUFLEN)>0) {
		received += recvBuf;
		memset(recvBuf, 0, sizeof recvBuf);
	}
	CheckReturnCode(received);
	cout << "You successfully unfollowed " << unfollow << "!\n";
}

string GetFriendIDs() {
	Connect();

	sprintf(toSend, "GET /friends/ids.xml HTTP/1.1\nHost: www.twitter.com\n%s\n", Authenticate());
	toSend[strlen(toSend)] = '\0';
	write(sockfd,&toSend,strlen(toSend));
	string received;
	string result = "follow=";
	size_t startPos = 0;
	size_t endPos = 0;
	while(read(sockfd, recvBuf, MAXBUFLEN) > 0) {
		received += recvBuf;
		memset(recvBuf, 0, sizeof recvBuf);
	}

	result = "follow=";

	startPos = received.find("<id>")+4;
	endPos = received.find("</id>");
	result += received.substr(startPos, endPos-startPos);
	received = received.substr(endPos+4);

	while(received.length() > 13) {
		startPos = received.find("<id>")+4;
		endPos = received.find("</id>");
		result += ",";
		result += received.substr(startPos, endPos-startPos);
		received = received.substr(endPos+4);
	}
	return result;
}

void Stream() {
	streamMode = true;
	string following = GetFriendIDs();
	ConnectToStream();
	sprintf(toSend, "POST /1/statuses/filter.xml HTTP/1.1\nHost: stream.twitter.com\n%sContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n%s", Authenticate(), following.length(), following.c_str());
	toSend[strlen(toSend)] = '\0';
	write(sockfd,&toSend,strlen(toSend));

	string received;
	string newStr;
	string oldStr;

	string tweet, author;
	string tweetStart = "<text>";
	string tweetEnd = "</text>";
	string authorStart = "<screen_name>";
	string authorEnd = "</screen_name>";
	int foundStart = 0;
	int foundEnd = 0;

	while(true) {
		if(streamMode == false) {
			break;
		}
		read(sockfd, recvBuf, MAXBUFLEN);
		received = recvBuf;
		size_t pos;
		pos = received.rfind("</status>")+9;
		newStr = oldStr + received.substr(0, pos);
		oldStr = received.substr(pos, received.size()-pos);
		memset(recvBuf, 0, sizeof recvBuf);

		while(true) {
			foundStart = newStr.find(tweetStart)+6;
			if (foundStart == string::npos) {
				break;
			}
			foundEnd = newStr.find(tweetEnd);
			if (foundEnd == string::npos) {
				break;
			}
			tweet.assign(newStr, foundStart, foundEnd-foundStart);
			newStr.assign(newStr, foundEnd, newStr.length()-foundEnd);

			foundStart = newStr.find(authorStart)+13;
			if (foundStart == string::npos) {
				break;
			}
			foundEnd = newStr.find(authorEnd);
			if (foundEnd == string::npos) {
				break;
			}
			author.assign(newStr, foundStart, foundEnd-foundStart);
			newStr.assign(newStr, foundEnd, newStr.length()-foundEnd);
			cout << "\n@" << author << endl << tweet << endl;

		}
		sleep(stream);
	}
}
