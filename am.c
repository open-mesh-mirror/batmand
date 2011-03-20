/*
 *
 * Authentication Module
 *
 * Used for creating a authentication channel, and other authentication purposes
 *
 * Created on : 1. feb. 2011
 * Author     : Espen Graarud
 * Email      : espengra@stud.ntnu.no
 * Project    : Implementing a Secure Ad Hoc Network
 * Institution: NTNU (Norwegian University of Science & Technology), ITEM (Institute of Telematics)
 *
 */

#include "am.h"

enum role_type my_role = NOT_AUTHENTICATED;
struct addrinfo hints, *res;
int32_t am_send_socket = 0;
int32_t am_recv_socket = 0;
pthread_t am_thread;
enum pthread_status am_status = READY;
//struct bat_packet *bat_packet;
//struct batman_if *batman_if;
int auth_thread_int = 99;
int32_t packet_len = 0;
struct challenge_packet *challenge_packet;
struct challenge_response_packet challenge_response_packet;
struct response_packet response_packet;
struct sockaddr_in sin_dest;
char *if_device;


//Temp variables
uint8_t bool_extended = 0;
uint8_t is_authenticated = 0;
uint8_t my_auth_token = 0;
uint8_t my_challenge = 0;
uint8_t my_response = 0;
uint8_t rcvd_challenge = 0;
uint8_t rcvd_response = 0;
uint8_t rcvd_auth_token = 0;
uint8_t expecting_token = 0;
uint8_t num_waits = 0;
uint32_t random_wait_time = 0;
uint8_t generated_challenge = 0;
uint8_t generated_request = 0;
uint8_t generated_auth = 0;
uint8_t tmp_response = 0;
uint32_t tmp_wait = 0;
uint8_t rcvd_role = 0;



//TODO: fill in these variables where necessary in later code....
void authenticate_thread_init(char *d, uint8_t auth_token, uint8_t role, char *prev_sender, char *my_addr_string) {
	if (am_status != IN_USE) {

		if_device = (char *) malloc(strlen(d)+1);
		memset(if_device, 0, strlen(d)+1);
		memcpy(if_device, d, strlen(d));
//		if_device[strlen(if_device)] = '\0'; 	//might have to be used like this, check if errors appear later...

		rcvd_auth_token = auth_token;

		rcvd_role = role;

		addr_prev_sender = (char *) malloc(strlen(prev_sender)+1);
		memset(addr_prev_sender, 0, strlen(prev_sender)+1);
		memcpy(addr_prev_sender, prev_sender, strlen(prev_sender));

		my_addr = (char *) malloc(strlen(my_addr_string)+1);
		memset(my_addr, 0, strlen(my_addr_string)+1);
		memcpy(my_addr, my_addr_string, strlen(my_addr_string));

		am_status = pthread_create(&am_thread, NULL, authenticate, NULL);

	}

}


void *authenticate() {

	setup_am_socks();

	if(my_role == NOT_AUTHENTICATED) {

		if (rcvd_auth_token > 0) {
			printf("rcvd_auth_token > 0\n");

			if(rcvd_role == MASTER)
				authenticate_with_sp();

		} else {

			if(inet_addr(addr_prev_sender) < inet_addr(my_addr)) {
//				printf("I have the greatest IP number\n");
				initiate_handshake();

			} else{
//				printf("I have the smallest IP number\n");
				wait_for_handshake();
			}
		}
	}

	am_status = READY;
	free(if_device);
	free(addr_prev_sender);
	free(my_addr);
	pthread_exit(NULL); //Necessary in order not to end a non-void function without a return value.
}

void setup_am_socks() {

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;

	memset((char *) &sin_dest, 0, sizeof(sin_dest));
	sin_dest.sin_family = AF_INET;
	sin_dest.sin_port = htons(64305);
	if (inet_aton(addr_prev_sender, &sin_dest.sin_addr)==0) {
		printf("inet_aton() failed\n");
		exit(1);
	}

	getaddrinfo(NULL, "64305", &hints, &res);
	setup_am_recv_sock();
	setup_am_send_sock();
}

void setup_am_recv_sock() {

	if ( (am_recv_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		printf("Error - can't create AM receive socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

//	if ( bind_to_iface( am_recv_socket, if_device ) < 0 ) {
//		printf("Cannot bind socket to device %s : %s \n", if_device, strerror(errno));
//		destroy_am_socks();
//	}

	setsockopt(am_recv_socket, SOL_SOCKET, SO_BINDTODEVICE, if_device, strlen(if_device) + 1);

//	bind(am_recv_socket, (struct sockaddr*)&sin_dest, sizeof(sin_dest));
	bind(am_recv_socket, res->ai_addr, res->ai_addrlen);

}

void setup_am_send_sock() {

	if ( (am_send_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		printf("Error - can't create AM send socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

//	if ( bind_to_iface( am_send_socket, if_device ) < 0 ) {
//		printf("Cannot bind socket to device %s : %s \n", if_device, strerror(errno));
//		destroy_am_socks();
//	}

	setsockopt(am_send_socket, SOL_SOCKET, SO_BINDTODEVICE, if_device, strlen(if_device) + 1);


}

void destroy_am_socks() {
//	printf("Destroying AM sockets\n");
	if (am_recv_socket != 0)
		close(am_recv_socket);

	if (am_send_socket != 0)
		close(am_send_socket);

	am_recv_socket = 0;
	am_send_socket = 0;

	freeaddrinfo(res);
}

//void wait_for_handshake(struct batman_if *batman_if) {
void wait_for_handshake() {
	if(recvfrom(am_recv_socket, &recvBuf, MAXBUFLEN - 1, 0, NULL, NULL) < 0) {
		printf("Error - can't receive packet: %s\n", strerror(errno));
	}

//	printf("\nTEST\n\n");// - strlen(prev_sender) = %d\n\n", strlen(prev_sender));

	rcvd_challenge_packet = (struct challenge_packet *)recvBuf;

	printf("Challenge Received: %d\n", rcvd_challenge_packet->challenge_value);
	destroy_am_socks();
}

/*void dump_memory(void* data, size_t len)
{
size_t i;
printf("Data in [%p..%p): ",data,data+len);
for (i=0;i<len;i++)
printf("%02X ", ((unsigned char*)data)[i] );
printf("\n");
}*/


void initiate_handshake() {
	printf("\ninitiate_handshake()\n");

	my_challenge = 1 + (rand() % UINT8_MAX);

	challenge_packet = (struct challenge_packet *) malloc(sizeof(struct challenge_packet));
	challenge_packet->role = my_role;
	challenge_packet->challenge_value = my_challenge;


//	challenge_packet.role = my_role;
//	challenge_packet.challenge_value = my_challenge;


	printf("Trying to send challenge value %d\n", challenge_packet->challenge_value);

	memset(&sendBuf, 0, sizeof(sendBuf));
	memcpy(&sendBuf, challenge_packet, sizeof(*challenge_packet));
	packet_len = sizeof(*challenge_packet);

//	dump_memory(&sendBuf, sizeof(sendBuf));
//	dump_memory(&challenge_packet, sizeof(challenge_packet));


	send_udp_packet((unsigned char *)&sendBuf, packet_len, &sin_dest, am_send_socket, NULL);
//	send_udp_packet((unsigned char *)&sendBuf, &packet_len, res->ai_addr, am_send_socket, NULL);

}

void authenticate_with_sp() {

}



