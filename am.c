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
//
//
//					if (rcvd_auth_token > 0) {
//
//						if(rcvd_challenge == 0) {
//
//							if(rcvd_response > 0) { //Receive RESPONSE
//
//								tmp_response = (2*generated_request) % UINT8_MAX;
//								tmp_response = (tmp_response == 0 ? 1 : tmp_response);
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (RESPONSE)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(rcvd_response == tmp_response) { //RESPONSE is correct
//
//									my_challenge = 0;
//									my_response = 0;
//									my_auth_token = rcvd_auth_token;
//									generated_challenge = 0;
//									generated_request = 0;
//									generated_auth = 0;
//									tmp_response = 0;
//									role = 1;
//									debug_output(4, "[SEND] %d | %d | %d (AUTH)\n", my_challenge, my_response, my_auth_token);
//									debug_output(4, "YOU ARE AUTHENTICATED!\n");
//	//								schedule_own_packet(batman_if);
//
//								} else { //RESPONSE is wrong
//
//									my_challenge = 0;
//									my_response = 0;
//									my_auth_token = 0;
//									tmp_response = 0;
//									debug_output(4, "RESPONSE IS WRONG\n");
//									tmp_wait = rand() % 10000;
//									random_wait_time = curr_time + tmp_wait;
//
//								}
//								debug_output(4, "========================================================\n");
//
//							} else { //Receive AUTH
//
//								my_challenge = 0;
//								my_response = 0;
//
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (AUTH)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(rcvd_auth_token == generated_auth) { //Receive AUTH (Last Message in Handshake)
//
//									role = 2;
//									my_auth_token = generated_auth;
//									generated_challenge = 0;
//									generated_request = 0;
//									generated_auth = 0;
//									debug_output(4, "YOU ARE MASTER NODE!\n");
//
//								}
//								debug_output(4, "========================================================\n");
//
//							}
//
//						} else {
//
//							if(rcvd_response == 0) { //Receive CHALLENGE FROM MASTER
//
//								if(generated_request == 0) {
//									generated_request = 1 + (rand() % UINT8_MAX);
//								}
//								my_challenge = generated_request;
//								my_response = (2*rcvd_challenge) % UINT8_MAX;
//								my_response = (my_response == 0 ? 1 : my_response);
//								my_auth_token = 0;
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[SEND] %d | %d | %d (REQUEST)\n", my_challenge, my_response, my_auth_token);
//								debug_output(4, "========================================================\n");
//
//							}
//
//
//
//						}
//
//
//					} else {
//						if(rcvd_challenge == 0) {
//
//							if(rcvd_response == 0) { //Receive PLAIN
//
//
//								if(curr_time > random_wait_time) {
//
//									debug_output(4, "========================================================\n");
//									debug_output(4, "[RECV] %d | %d | %d (PLAIN)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//									usleep(rand() % 100000);
//
//									if(generated_challenge==0) {
//										generated_challenge = 1 + (rand() % UINT8_MAX);
//									}
//
//									my_challenge = generated_challenge;
//									my_response = 0;
//									my_auth_token = 0;
//
//									debug_output(4, "[SEND] %d | %d | %d (CHALLENGE)\n", my_challenge, my_response, my_auth_token);
//									debug_output(4, "========================================================\n");
//	//								schedule_own_packet(batman_if);
//
//								}
//
//							}
//
//						} else {
//
//							if(rcvd_response == 0) { //Receive CHALLENGE
//
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (CHALLENGE)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(my_challenge > 0) { //Received CHALLENGE when I have sent CHALLENGE (COLLISION)
//
//									my_challenge = 0;
//									my_response = 0;
//									my_auth_token = 0;
//
//									debug_output(4, "COLLISION!\n");
//
//									tmp_wait = rand() % 10000;
//									random_wait_time = curr_time + tmp_wait;
//
//								} else { //Received CHALLENGE
//
//									if((generated_challenge == 0) || (curr_time > random_wait_time-(tmp_wait/2))) {
//										//if gen = 0 -> ingen tidligere sendte challenges så bare å kjøre på
//										//if halve ventetiden er over, kan man begynne å godta challenges
//
//										if(generated_request == 0) {
//											generated_request = 1 + (rand() % UINT8_MAX);
//										}
//
//										my_challenge = generated_request;
//										my_response = (2*rcvd_challenge) % UINT8_MAX;
//										my_response = (my_response == 0 ? 1 : my_response);
//										my_auth_token = 0;
//										debug_output(4, "[SEND] %d | %d | %d (REQUEST)\n", my_challenge, my_response, my_auth_token);
//	//									schedule_own_packet(batman_if);
//
//									} else {
//										debug_output(4, "WAITING\n");
//									}
//
//								}
//								debug_output(4, "========================================================\n");
//
//							} else { //Receive REQUEST
//								tmp_response = (2*generated_challenge) % UINT8_MAX;
//								tmp_response = (tmp_response == 0 ? 1 : tmp_response);
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (REQUEST)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(rcvd_response == tmp_response) { //REQUEST is correct
//
//									my_challenge = 0;
//									my_response = (2*rcvd_challenge) % UINT8_MAX;
//									my_response = (my_response == 0 ? 1 : my_response);
//
//									if(generated_auth == 0) {
//										generated_auth = 1 + (rand() % UINT8_MAX);
//									}
//
//									my_auth_token = generated_auth;
//									debug_output(4, "[SEND] %d | %d | %d (RESPONSE)\n", my_challenge, my_response, my_auth_token);
//	//								schedule_own_packet(batman_if);
//
//								} else { //REQUEST is wrong
//
//									my_challenge = 0;
//									my_response = 0;
//									my_auth_token = 0;
//									tmp_response = 0;
//									debug_output(4, "REQUEST IS WRONG\n");
//									tmp_wait = rand() % 10000;
//									random_wait_time = curr_time + tmp_wait;
//
//								}
//								debug_output(4, "========================================================\n");
//							}
//
//						}
//					}
//
//					goto send_packets;
//
//				} else if(role == 1) {
//					//Authenticated node
//					if(rcvd_auth_token != my_auth_token) {
//						goto send_packets;
//					}
//
//
//				} else {
//					//Master node
//					if(rcvd_auth_token == 0) {
//
//						if(rcvd_challenge == 0) {
//
//							if(rcvd_response == 0) { //Receive PLAIN
//
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (PLAIN)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(generated_challenge==0) {
//									generated_challenge = 1 + (rand() % UINT8_MAX);
//								}
//
//								my_challenge = generated_challenge;
//								my_response = 0;
//
//								debug_output(4, "[SEND] %d | %d | %d (CHALLENGE)\n", my_challenge, my_response, my_auth_token);
//								debug_output(4, "========================================================\n");
//
//							}
//
//						} else {
//
//							if(rcvd_response > 0) { //Received REQUEST
//
//								tmp_response = (2*generated_challenge) % UINT8_MAX;
//								tmp_response = (tmp_response == 0 ? 1 : tmp_response);
//								debug_output(4, "========================================================\n");
//								debug_output(4, "[RECV] %d | %d | %d (REQUEST)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);
//
//								if(rcvd_response == tmp_response) { //REQUEST is correct
//
//									my_challenge = 0;
//									my_response = (2*rcvd_challenge) % UINT8_MAX;
//									my_response = (my_response == 0 ? 1 : my_response);
//
//									debug_output(4, "[SEND] %d | %d | %d (RESPONSE)\n", my_challenge, my_response, my_auth_token);
//
//								}
//								debug_output(4, "========================================================\n");
//
//							}
//
//						}
//
//						goto send_packets;
//
//					} else if(rcvd_auth_token != my_auth_token) {//Receieve OGM from node in another MANET, auth token > 0, but not the same as the masters auth token
//						goto send_packets;
//					}
//				}

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



