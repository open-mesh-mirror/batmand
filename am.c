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
struct bat_packet *bat_packet;
struct batman_if *batman_if;
int auth_thread_int = 99;


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




void authenticate_thread_init(struct bat_packet *bp, struct batman_if *bi) {
	if (am_status != IN_USE) {
		bat_packet = bp;
		batman_if = bi;
		am_status = pthread_create(&am_thread, NULL, authenticate, NULL);
	}

}


void *authenticate() {

	printf("====================================\nauthenticate()\n====================================\n");

	rcvd_auth_token = bat_packet->auth_token;
	rcvd_role = bat_packet->role;

	char recvBuf[MAXBUFLEN] = {0};

	setup_am_socks(batman_if->dev);

	if(my_role == NOT_AUTHENTICATED) {

		if (rcvd_auth_token > 0) {
			printf("rcvd_auth_token > 0\n");

			if(rcvd_role == MASTER)
				authenticate_with_sp();

			if(rcvd_role == AUTHENTICATED)
				handshake_with_pc1();

		} else {
			printf("rcvd_auth_token == 0\n");

			if(bat_packet->prev_sender < (uint32_t)batman_if->addr.sin_addr.s_addr) {
				printf("I have the greatest IP number\n");
				initiate_handshake(batman_if);

			} else{
				printf("I have the smallest IP number\n");
				wait_for_handshake(batman_if);
			}
		}
	}

	am_status = READY;
}

void setup_am_socks(char *dev) {

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "64305", &hints, &res);

	setup_am_recv_sock(dev);
	setup_am_send_sock(dev);
}

void setup_am_recv_sock(char *dev) {
	printf("Attempting to create AM receive socket\n");
	if ( (am_recv_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0 ) {
		printf("Error - can't create AM receive socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

	if ( bind_to_iface( am_recv_socket, dev ) < 0 ) {
		printf("Cannot bind socket to device %s : %s \n", dev, strerror(errno));
		destroy_am_socks();
	}

	bind(am_recv_socket, res->ai_addr, res->ai_addrlen);

	printf("Successfully created AM receive socket\n");
}

void setup_am_send_sock(char *dev) {
	printf("Attempting to create AM send socket\n");
	if ( (am_send_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0 ) {
		printf("Error - can't create AM send socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

	if ( bind_to_iface( am_send_socket, dev ) < 0 ) {
		printf("Cannot bind socket to device %s : %s \n", dev, strerror(errno));
		destroy_am_socks();
	}

	printf("Successfully created AM send socket\n");
}

void destroy_am_socks() {
	printf("Destroying AM sockets\n");
	if (am_recv_socket != 0)
		close(am_recv_socket);

	if (am_send_socket != 0)
		close(am_send_socket);

	am_recv_socket = 0;
	am_send_socket = 0;

	freeaddrinfo(res);
}

void wait_for_handshake(struct batman_if *batman_if) {
	printf("\n====================================\nwait_for_handshake()\n====================================\n");
	int rcvd_packet_size;

	if(rcvd_packet_size = recvfrom(am_recv_socket, &recvBuf, MAXBUFLEN - 1, 0, &batman_if->addr, sizeof(&batman_if->addr)) == sizeof(struct challenge_packet)) {
		struct challenge_packet *rcvd_challenge_packet = recvBuf;
		memset(recvBuf, 0, sizeof(recvBuf));
		printf("FOUND THE CHALLENGE!\n");
	}
	memset(recvBuf, 0, sizeof(recvBuf));

}

void initiate_handshake(struct batman_if *batman_if) {
	printf("\n====================================\ninitiate_handshake()\n====================================\n");

	my_challenge = 1 + (rand() % UINT8_MAX);

	struct challenge_packet *challenge_packet;
	challenge_packet = (struct challenge_packet *) malloc(sizeof(struct challenge_packet));
	challenge_packet->role = my_role;
	challenge_packet->challenge_value = my_challenge;

//	send_udp_packet(challenge_packet, sizeof(challenge_packet), &batman_if->addr, batman_if->udp_send_sock, NULL);

	if ( sendto( am_send_socket, challenge_packet, sizeof(challenge_packet), 0, &batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {
		if ( errno == 1 ) {
			printf("Error - can't send UDP packet: %s.\n", strerror(errno));
			printf("Does your Firewall allow outgoing packets on port 64305?\n");
		} else {
			printf("Error - can't send UDP packet: %s\n", strerror(errno));
		}
		return -1;
	}

}

void authenticate_with_sp() {

}


void handshake_with_pc1() {

}



