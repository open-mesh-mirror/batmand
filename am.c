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

uint8_t role = 0;

void authenticate(struct bat_packet *bat_packet) {
	debug_output(4, "\n====================================\nauthenticate()\n====================================\n");
	rcvd_challenge = bat_packet->challenge;
	rcvd_response = bat_packet->response;
	rcvd_auth_token = bat_packet->auth_token;
	debug_output(4, "\n====================================\nrcvd_challenge = %d\nrcvd_response = %d\nrcvd_auth_token = %d\n====================================\n", rcvd_challenge, rcvd_response, rcvd_auth_token);


}


void authenticate_with_sp() {

}


void handshake_with_pc1() {

}



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
