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

uint8_t my_role = 0;
struct addrinfo hints, *res;
int32_t am_send_socket = 0;
int32_t am_recv_socket = 0;


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

uint32_t ogm_count = 0;





void authenticate(struct bat_packet *bat_packet, struct batman_if *batman_if) {

	debug_output(4, "\n====================================\nauthenticate()\n====================================\n");

	rcvd_auth_token = bat_packet->auth_token;
	rcvd_role = bat_packet->role;

	char recvBuf[MAXBUFLEN] = {0};

	setup_am_socks(batman_if->dev);

	if(my_role == 0) {

		if (rcvd_auth_token > 0) {
			debug_output(4, "rcvd_auth_token > 0\n");

			if(rcvd_role == 2) {
				authenticate_with_sp();

			} else if(rcvd_role == 1) {
				handshake_with_pc1();

			} else {
				return;
			}
		} else {
			debug_output(4, "rcvd_auth_token == 0\n");

			if(bat_packet->prev_sender < (uint32_t)batman_if->addr.sin_addr.s_addr) {
				debug_output(4, "I have the greatest IP number\n");
				initiate_handshake(batman_if);

			} else{
				debug_output(4, "I have the smallest IP number\n");
				wait_for_handshake(batman_if);
			}
		}
	}
}

void setup_am_socks(char *dev) {

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, "64305", &hints, &res);

	setup_am_recv_sock();
	setup_am_send_sock();
}

void setup_am_recv_sock() {
	debug_output(4, "Attempting to create AM receive socket\n");
	if ( (am_recv_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0 ) {
		debug_output(4, "Error - can't create AM receive socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

	if ( bind_to_iface( am_recv_socket, dev ) < 0 ) {
		debug_output(3, "Cannot bind socket to device %s : %s \n", dev, strerror(errno));
		destroy_am_socks();
	}

	bind(am_recv_socket, res->ai_addr, res->ai_addrlen);

	debug_output(4, "Successfully created AM receive socket\n");
}

void setup_am_send_sock() {
	debug_output(4, "Attempting to create AM send socket\n");
	if ( (am_send_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0 ) {
		debug_output(4, "Error - can't create AM send socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

	if ( bind_to_iface( am_send_socket, dev ) < 0 ) {
		debug_output(3, "Cannot bind socket to device %s : %s \n", dev, strerror(errno));
		destroy_am_socks();
	}

	debug_output(4, "Successfully created AM send socket\n");
}

void destroy_am_socks() {
	debug_output(4, "Destroying AM sockets\n");
	if (am_recv_socket != 0)
		close(am_recv_socket);

	if (am_send_socket != 0)
		close(am_send_socket);

	am_recv_socket = 0;
	am_send_socket = 0;

	freeaddrinfo(res);
}

void wait_for_handshake(struct batman_if *batman_if) {
	debug_output(4, "\n====================================\nwait_for_handshake()\n====================================\n");
	int rcvd_packet_size;
	//TODO: Create a loop to look through all the received packets, as the buffer will be full of regular OGMs as well as the challenge packet.
	int i;
	for(i=0; i<50; i++) {
		if(rcvd_packet_size = recvfrom(batman_if->udp_recv_sock, &recvBuf, MAXBUFLEN - 1, 0, &batman_if->addr, sizeof(&batman_if->addr)) == sizeof(struct challenge_packet)) {
			struct challenge_packet *rcvd_challenge_packet = recvBuf;
			memset(recvBuf, 0, sizeof(recvBuf));
			debug_output(4, "FOUND THE CHALLENGE!\n");
			break;
		}
		memset(recvBuf, 0, sizeof(recvBuf));
	}

	return;
}

void initiate_handshake(struct batman_if *batman_if) {
	debug_output(4, "\n====================================\ninitiate_handshake()\n====================================\n");

	my_challenge = 1 + (rand() % UINT8_MAX);

	struct challenge_packet *challenge_packet;
	challenge_packet = (struct challenge_packet *) malloc(sizeof(struct challenge_packet));
	challenge_packet->role = my_role;
	challenge_packet->challenge_value = my_challenge;

	int i;
	while(1) {
		send_udp_packet(challenge_packet, sizeof(challenge_packet), &batman_if->addr, batman_if->udp_send_sock, NULL);
	}

	return;
}

void authenticate_with_sp() {

}


void handshake_with_pc1() {

}



