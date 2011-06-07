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

void *KDF1_SHA256(const void *in, size_t inlen, void *out, size_t *outlen) {

    if (*outlen < SHA256_DIGEST_LENGTH) {
    	return NULL;
    }
    else {
        *outlen = SHA256_DIGEST_LENGTH;
    }
    return SHA256(in, inlen, out);
}

void * secure_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body) {

	secure_t *cryptex = malloc(sizeof(secure_head_t) + key + mac + body);
	secure_head_t *head = (secure_head_t *)cryptex;
	head->length.key = key;
	head->length.mac = mac;
	head->length.orig = orig;
	head->length.body = body;

	return cryptex;
}

void * secure_body_data(secure_t *cryptex) {
	secure_head_t *head = (secure_head_t *)cryptex;
	return (char *)cryptex + (sizeof(secure_head_t) + head->length.key + head->length.mac);
}

void * secure_mac_data(secure_t *cryptex) {
	secure_head_t *head = (secure_head_t *)cryptex;
	return (char *)cryptex + (sizeof(secure_head_t) + head->length.key);
}

/* Debugging purposes */
void tool_dump_memory(unsigned char* data, size_t len) {
	size_t i;
	printf("Data in [%p..%p): ",data,data+len);
	for (i=0;i<len;i++) {
		if(!(i%32)) {
			printf("\n[%4d - %4d]: ",i, ( i+32 <= len ? i+32 : len ));
		}
		printf("%02X ", ((unsigned char*)data)[i]);
	}
	printf("\n");
}

/* External Variables */
role_type my_role, req_role;
am_state my_state;
pthread_t am_main_thread;
uint32_t new_neighbor, prev_neighbor;
//uint32_t trusted_neighbors[100];
unsigned char *auth_value;
int auth_value_len;
uint16_t auth_seq_num;

trusted_node *authenticated_list[100];
trusted_neigh *neigh_list[100];
int num_auth_nodes, num_trusted_neigh;

pthread_mutex_t auth_lock = PTHREAD_MUTEX_INITIALIZER;



/* Variables used by whole AM class */
pthread_t am_thread;
sockaddr_in my_addr, broadcast_addr;
char *interface;
uint16_t my_id;
int32_t am_send_socket, am_recv_socket;
unsigned char *current_key = NULL;
time_t last_send_time;

/* Usage function for my AM extension */
secure_usage() {
	fprintf( stderr, "Secure Usage: batman [options] -R/--role 'sp/authenticated/restricted' interface [interface interface]\n" );
	fprintf( stderr, "       -R / --role 'sp'              start as Service Proxy / Master node\n" );
	fprintf( stderr, "       -R / --role 'authenticated'   request to become authenticated with full rights\n" );
	fprintf( stderr, "       -R / --role 'restricted'      request to become restricted (end-node only)\n" );
}

/* Function called from batman.c that creates a separate AM main thread */
void am_thread_init(char *dev, sockaddr_in addr, sockaddr_in broad) {
	/* Set my address and broadcast address of interface */
	my_addr = addr;
	broadcast_addr = broad;
	broadcast_addr.sin_family = AF_INET;
	broadcast_addr.sin_port = htons(AM_PORT);

	/* Set interface name */
	interface = (char *) malloc(strlen(dev)+1);
	memset(interface, 0, strlen(dev)+1);
	strncpy(interface, dev, strlen(dev));

	/* Create the am main thread */
	pthread_create(&am_main_thread, NULL, am_main, NULL);
}

void am_thread_kill() {
	pthread_kill(&am_main_thread);
	int i;
	for(i=0; i<num_auth_nodes; i++) {
		free(authenticated_list[i]->name);
		free(authenticated_list[i]->pub_key);
		free(authenticated_list[i]);
	}
	for(i=0; i<num_trusted_neigh; i++) {
		free(neigh_list[i]->mac);
		free(neigh_list[i]);
	}
	free(interface);
	free(auth_value);
	socks_am_destroy(&am_send_socket, &am_recv_socket);

}


/* AM main thread */
void *am_main() {

	sockaddr_in *dst;
	sockaddr_storage recv_addr;
	socklen_t addr_len;
	fd_set readfds;
	timeval tv;

	char am_recv_buf[MAXBUFLEN];
	char *am_recv_buf_ptr;
	char am_send_buf[MAXBUFLEN];
	char *am_send_buf_ptr;
	char *am_payload_ptr;

	unsigned char *subject_name = NULL;

	ssize_t data_rcvd;

	am_type am_type_rcvd;

	char *auth_pkt = NULL;

	EVP_PKEY *tmp_pub, *pkey = NULL;
	EVP_CIPHER_CTX aes_master;


	int key_count = 0;
	int rcvd_id;
	time_t test_timer, state_timer;



	/* Load all algorithms and error messages used by OpenSSL */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Setup socks for the all AM purposes, except initial authentication */
	socks_am_setup(&am_recv_socket, &am_send_socket);

	/* Clear the set */
	FD_ZERO(&readfds);

	/* Add descriptor (receiver socket) to set */
	FD_SET(am_recv_socket, &readfds);

	/* Set time interval for checking the socket */
	tv.tv_sec = 0;
	tv.tv_usec = 100000;

	/* Set user ID */
	char addr_char[16];
	inet_ntop( AF_INET, &(my_addr.sin_addr.s_addr), addr_char, sizeof (addr_char) );
	my_id = inet_addr(addr_char) % UINT16_MAX;

	/* Generate Master Key and bind it to AES context*/
	openssl_key_master_ctx(&aes_master);

	num_trusted_neigh = 0;
	num_auth_nodes = 0;
	if(my_role == SP) {

		/* If you are the SP, create a PC0 */
		subject_name = malloc(SUBJECT_NAME_SIZE);
		openssl_cert_create_pc0(&pkey, &subject_name);

		/* Create & Send Signed RANDOM Data (for continuous authentication) */
//		all_sign_send(&aes_master, &key_count, &auth_pkt);

		/* Initiate AL with yourself in it */
		al_add(my_addr.sin_addr.s_addr, my_id, SP, subject_name, pkey);


	}

	/* Else create a PC Request	 */
	else {
		openssl_cert_create_req(&pkey, subject_name);
	}


	data_rcvd = 0;
	addr_len = sizeof recv_addr;
	am_recv_buf_ptr = am_recv_buf;
	am_send_buf_ptr = am_send_buf;
	am_payload_ptr = NULL;
	dst = NULL;

//	uint16_t testint = 40960;
//	int tmpsda;
//	for (tmpsda = 0; tmpsda<16; tmpsda++) {
//		printf("[%2d] %d + 1 = ", tmpsda, testint);
//		testint = testint | 1;
//		printf("%d\n", testint);
//		testint = testint >> 1;
//	}
//	exit(1);
	/* Main loop for the AM thread, will only exit when Batman is terminated */
	while(1) {

		/* Check For Incoming Data On AM Socket */
		FD_ZERO(&readfds);
		FD_SET(am_recv_socket, &readfds);

		select(am_recv_socket+1, &readfds, NULL, NULL, &tv);
		if(FD_ISSET(am_recv_socket,&readfds)) {
			memset(&am_recv_buf, 0, MAXBUFLEN);
			data_rcvd = recvfrom(am_recv_socket, &am_recv_buf, MAXBUFLEN - 1, 0, (sockaddr *)&recv_addr, &addr_len);
		}

		if(data_rcvd) {
			am_type_rcvd = am_header_extract(am_recv_buf_ptr, &am_payload_ptr, &rcvd_id);

			in_addr neigh_addr;
			neigh_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;

			switch (am_type_rcvd) {

				case SIGNATURE:
					/* Allowed in all states */
					neigh_sign_recv(pkey, neigh_addr.s_addr, rcvd_id, am_payload_ptr);
					break;

				case NEIGH_SIGN:
					/* Allowed in all states */
					neigh_sign_recv(pkey, neigh_addr.s_addr, rcvd_id, am_payload_ptr);
					if(my_state == WAIT_FOR_NEIGH_SIG)
						my_state = READY;

					if (my_state == WAIT_FOR_NEIGH_SIG_ACK) {

						neigh_list_add(dst->sin_addr.s_addr, rcvd_id, NULL);

						al_add(dst->sin_addr.s_addr, rcvd_id, AUTHENTICATED, subject_name, tmp_pub);

						if(pthread_mutex_trylock(&auth_lock) == 0) {
							if(num_trusted_neigh == 1) {
								auth_pkt = all_sign_send(pkey, &aes_master, &key_count);
							} else {
								neigh_sign_send(pkey, dst, auth_pkt);
							}
							pthread_mutex_unlock(&auth_lock);
						}

						free(dst);
					}
					break;

				case AL_FULL:
					/* Allowed in all states, must not be SP */
					if(my_role == AUTHENTICATED) {
						//TODO: Overwrite current local AL
					}
					break;

				case AL_ROW:
					/* Allowed in all states, must not be SP */
					if(my_role == AUTHENTICATED) {
						//TODO: Append to local AL, maybe check to see if node already exists for error handling?
					}
					break;

				case AUTH_INVITE:
					/* Must be unauthenticated */
					if(my_role == UNAUTHENTICATED && my_state == READY) {

						if(auth_invite_recv(am_payload_ptr)) {
							my_state = SEND_REQ;
							dst = (sockaddr_in *) malloc(sizeof(sockaddr_in));
							dst->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
							dst->sin_family = AF_INET;
							dst->sin_port = htons(AM_PORT);
							auth_request_send(dst);
							my_state = WAIT_FOR_PC;
							free(dst);
						}

					}

					break;

				case AUTH_REQ:
					/* Must be SP and waiting for req*/
					if(my_role == SP && my_state == WAIT_FOR_REQ) {
						my_state = SEND_PC;

						if((uint32_t)((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr.s_addr == prev_neighbor) {

							char *recv_addr_string = inet_ntoa(((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr);
							if(auth_request_recv(recv_addr_string, am_payload_ptr)) {

								dst = (sockaddr_in *) malloc(sizeof(sockaddr_in));
								dst->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
								dst->sin_family = AF_INET;
								dst->sin_port = htons(AM_PORT);
								openssl_cert_create_pc1(&tmp_pub, recv_addr_string, &subject_name);
								auth_issue_send(dst);

//
//								neigh_list_add(dst->sin_addr.s_addr, rcvd_id, NULL);
//
//								al_add(dst->sin_addr.s_addr, rcvd_id, AUTHENTICATED, subject_name, tmp_pub);
//
//								if(pthread_mutex_trylock(&auth_lock) == 0) {
//									if(num_trusted_neigh == 1) {
//										auth_pkt = all_sign_send(pkey, &aes_master, &key_count);
//									} else {
//										neigh_sign_send(pkey, dst, auth_pkt);
//									}
//									pthread_mutex_unlock(&auth_lock);
//								}
//
//								free(dst);

								my_state = WAIT_FOR_NEIGH_SIG_ACK;

							}


						} else {
							printf("Request from unknown node!\n");
						}
					}

					prev_neighbor = 0;
					my_state = READY;

					break;

				case AUTH_ISSUE:
					/* Must be unauthenticated */
					if(my_role == UNAUTHENTICATED && my_state == WAIT_FOR_PC) {

						if(auth_issue_recv(am_payload_ptr)) {
							my_state = READY;
							my_role = AUTHENTICATED;

							in_addr emptyaddr;
							emptyaddr.s_addr = 0;
							openssl_cert_read(emptyaddr , &subject_name, &tmp_pub);
							neigh_list_add(neigh_addr.s_addr, rcvd_id, NULL);
							al_add(neigh_addr.s_addr, rcvd_id, SP, subject_name, tmp_pub);
							printf("1\n");
							EVP_PKEY_free(tmp_pub);
							printf("2\n");

							if(pthread_mutex_trylock(&auth_lock) == 0) {
								auth_pkt = all_sign_send(pkey, &aes_master, &key_count);
								pthread_mutex_unlock(&auth_lock);
							}
						}
					}

					break;

				case NEIGH_PC_REQ:
					
					/* Receive Neighbors PC */
					neigh_pc_recv(neigh_addr, am_payload_ptr);

					if(!openssl_cert_read(neigh_addr, &subject_name, &tmp_pub))
						break;

					/* Verify PC Rights (ProxyCertInfo) */
					//TODO:Check access rights policy

					al_add(neigh_addr.s_addr, rcvd_id, AUTHENTICATED, subject_name, tmp_pub);
					EVP_PKEY_free(tmp_pub);

					/* Send own PC */
					dst = (sockaddr_in *) malloc(sizeof(sockaddr_in));
					dst->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
					dst->sin_family = AF_INET;
					dst->sin_port = htons(AM_PORT);
					neigh_pc_send(dst);

					/* Send Signature */
					neigh_sign_send(pkey, dst, auth_pkt);

					my_state = WAIT_FOR_NEIGH_SIG;

					free(dst);

					break;

				case NEIGH_PC:

					if(my_state == WAIT_FOR_NEIGH_PC) {
						/* Receive Neighbors PC */
						neigh_pc_recv(neigh_addr, am_payload_ptr);
						openssl_cert_read(neigh_addr, &subject_name, &tmp_pub);
//						neigh_list_add(neigh_addr.s_addr, rcvd_id, NULL);
						al_add(neigh_addr.s_addr, rcvd_id, AUTHENTICATED, subject_name, tmp_pub);

						dst = (sockaddr_in *) malloc(sizeof(sockaddr_in));
						dst->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
						dst->sin_family = AF_INET;
						dst->sin_port = htons(AM_PORT);

						neigh_sign_send(pkey, dst, auth_pkt);

						free(dst);
						my_state = WAIT_FOR_NEIGH_SIG;
//						new_neighbor = 0;
					}
					break;

				default:
					printf("Received unknown AM Type %d, exiting with condition 1\n",am_type_rcvd);
					exit(1);
			}
			data_rcvd = 0;
		}

		/* If BATMAN has found a new direct neighbor */
		if(new_neighbor && my_state == READY) {

			dst = (sockaddr_in *) malloc(sizeof(sockaddr_in));
			dst->sin_addr.s_addr = new_neighbor;
			dst->sin_family = AF_INET;
			dst->sin_port = htons(AM_PORT);

			/*Check if node is in AL */
			int i;
			for(i=0; i<num_auth_nodes; i++) {

				if(new_neighbor == authenticated_list[i]->addr) {

					/* Send Signature */
					neigh_sign_send(pkey, dst, auth_pkt);

					/* Check whether neighbor sent you sig first */
					//TODO: maybe for-loop through this, might not be last one if many new neighs at same time...
					if(neigh_list[num_trusted_neigh-1]->addr != new_neighbor)
						my_state = WAIT_FOR_NEIGH_SIG;

					break;

				}
			}

			/* Not in AL, add to AL before neigh_list */
			if(i == num_auth_nodes) {

				/* If SP invite to handshake */
				if(my_role == SP) {
					my_state = WAIT_FOR_REQ;
					auth_invite_send(dst);
					prev_neighbor = new_neighbor;
				}

				/* If just AUTHENTICATED exchange PCs and SIGNs */
				if(my_role == AUTHENTICATED) {

					/* Only one can initiate the neighbor's pc request or else collision */
					if(my_addr.sin_addr.s_addr < new_neighbor) {
						my_state = WAIT_FOR_NEIGH_PC;
						neigh_req_pc_send(dst);
					}

				}

			}

			new_neighbor = 0;
			free(dst);

		}

		/* Check if more than 60 seconds since last all_sign_send */
		test_timer = time (NULL);
		if(last_send_time != 0 && (test_timer - 60 > last_send_time) && (my_state == READY)) {
			printf("Time to send new SIGN message to all neighbors!\n");
			free(auth_pkt);
			auth_pkt = all_sign_send(pkey, &aes_master, &key_count);
		}

		/* If most of keystream is used, make new */
		if(auth_seq_num > 0.9*(auth_value_len/2)) {
			printf("Used more than 90 percent of keystream, time to make new!\n");
			free(auth_pkt);
			auth_pkt = all_sign_send(pkey, &aes_master, &key_count);
		}

		/* Check whether some neighbors should be purged */
		{
			int i;
			for(i=0;i<num_trusted_neigh;i++) {

				if(test_timer - 130 > neigh_list[i]->last_rcvd_time){
					printf("Not received new keystream from #'%d' in 130 seconds, removing from neighbor list!\n", neigh_list[i]->id);
					neig_list_remove(i);

					/* If found, list is changing, so wait till next run before removing more */
					break;
				}

			}
		}

		/* Check state, if state not READY for a while (3 seconds), go to READY */
		if(my_state != READY) {
			if(state_timer==0)
				state_timer = time(NULL);

			if(test_timer - 3 > state_timer) {
				my_state = READY;
				state_timer = 0;
			}

		}else {

			/* Make sure state_timer is zero if state is ready! */
			if(state_timer!=0)
				state_timer=0;
		}

	}
	free(subject_name);
	pthread_exit(NULL);
}


/* Add node to Authenticated List */
void al_add(uint32_t addr, uint16_t id, role_type role, unsigned char *subject_name, EVP_PKEY *key) {

	authenticated_list[num_auth_nodes] = malloc(sizeof(trusted_node));
	authenticated_list[num_auth_nodes]->addr = addr;
	authenticated_list[num_auth_nodes]->id = id;
	authenticated_list[num_auth_nodes]->role = role;
	authenticated_list[num_auth_nodes]->name = malloc(FULL_SUB_NM_SZ);
	memcpy(authenticated_list[num_auth_nodes]->name, subject_name, FULL_SUB_NM_SZ);
	authenticated_list[num_auth_nodes]->pub_key = openssl_key_copy(key);

	printf("\nAdded new node to AL:\n");
	printf("ID           : %d\n", authenticated_list[num_auth_nodes]->id);

	char addr_char[16];

	addr_to_string(authenticated_list[num_auth_nodes]->addr, &addr_char, sizeof (addr_char));

	printf("IP ADDRESS   : %s\n", addr_char);
	if(authenticated_list[num_auth_nodes]->role == 3) {
		printf("ROLE         : Service Proxy Node\n");
	} else {
		printf("ROLE         : Authenticated Node\n");
	}
	printf("Subject Name : %s\n", authenticated_list[num_auth_nodes]->name);
	printf("Public Key   :\n");
	PEM_write_PUBKEY(stdout,authenticated_list[num_auth_nodes]->pub_key);
	printf("\n");

	if(id != my_id) {
		EVP_PKEY_free(key);
	}

	num_auth_nodes++;

}

/* Add node to trusted neighbor list */
void neigh_list_add(uint32_t addr, uint16_t id, unsigned char *mac_value) {

	int i;
	for(i=0; i<num_trusted_neigh; i++) {
		if(id == neigh_list[i]->id) {

			if(addr == neigh_list[i]->addr) {

				if(neigh_list[i]->mac != NULL)
					free(neigh_list[i]->mac);

				neigh_list[i]->mac = mac_value;
				neigh_list[i]->window = 0;
				neigh_list[i]->last_seq_num = 0;
				neigh_list[i]->last_rcvd_time = time (NULL);

				printf("Added new keystream to node already in neighbor list\n");

			} else {

				printf("New address does not match previously stored address, removing node from list\n");

				if (mac_value != NULL)
					free(mac_value);

				neig_list_remove(i);
			}
			break;
		}
	}

	if(i==num_trusted_neigh) {

		neigh_list[num_trusted_neigh] = malloc(sizeof(trusted_neigh));
		neigh_list[num_trusted_neigh]->addr = addr;
		neigh_list[num_trusted_neigh]->id = id;
		neigh_list[num_trusted_neigh]->mac = mac_value;
		neigh_list[i]->window = 0;
		neigh_list[num_trusted_neigh]->last_seq_num = 0;
		neigh_list[num_trusted_neigh]->last_rcvd_time = time (NULL);
		num_trusted_neigh++;

		printf("Added new node to neighbor list\n");

	}

}

/* Remove from Neighbor List */
int neig_list_remove(int pos) {

	/* First check whether this node exists at all (sanity check) */
	if(neigh_list[pos] == NULL) {
		printf("Node does not exist in NL, cannot remove!\n");
		return 0;
	}

	/* Check whether keystream exists, remove if so! */
	if(neigh_list[pos]->mac != NULL)
		free(neigh_list[pos]->mac);

	/* Free up neighbor in memory */
	free(neigh_list[pos]);

	/* Re-arrange Neighbor List to avoid scarce population */
	int i;
	for(i=pos+1; i<num_trusted_neigh; i++) {
		neigh_list[i-1] = neigh_list[i];
	}

	/* Finally, number of trusted neighbors has shrunk :) */
	num_trusted_neigh--;

	return 1;
}

/* Create RAND for Routing Auth Data */
void openssl_tool_gen_rand(unsigned char **rv, int len) {
	if(*rv == NULL || rv == NULL) {
		*rv = malloc(len);
	}
	RAND_pseudo_bytes(*rv,len);
}

/* Create PC0 for the SP */
int openssl_cert_create_pc0(EVP_PKEY **pkey, unsigned char **subject_name) {

	X509 *pc0 = NULL;
	FILE *fp;
	BIO *bio_err;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

	openssl_cert_selfsign(&pc0, pkey, subject_name);

//	RSA_print_fp(stdout,pkey->pkey.rsa,0);
//	EC_KEY_print_fp(stdout, pkey->pkey.ec_key, 0);
//	X509_print_fp(stdout,pc0);

//	PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
//	PEM_write_X509(stdout,pc0);

	/* Write X509 PC0 to a file */
	if(!(fp = fopen(MY_CERT, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_CERT);
	if(PEM_write_X509(fp, pc0) != 1)
		fprintf(stderr, "Error while writing request to file %s", MY_CERT);
	fclose(fp);

	/* Write Private Key to a file */
	if(!(fp = fopen(MY_KEY, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_KEY);
	if(PEM_write_PrivateKey(fp, *pkey, NULL, NULL, 0, NULL, NULL) != 1)
		fprintf(stderr, "Error while writing the RSA private key to file %s\n", MY_KEY);
	fclose(fp);

	X509_free(pc0);
//	EVP_PKEY_free(pkey);

#ifdef CUSTOM_EXT
	/* Only needed if we add objects or custom extensions */
	X509V3_EXT_cleanup();
	OBJ_cleanup();
#endif

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);

}

/* Create PC REQ for an UNAUTHENTICATED Node */
int openssl_cert_create_req(EVP_PKEY **pkey, unsigned char *subject_name) {

	X509_REQ *req;
	FILE *fp;
	BIO *bio_err;

	req = NULL;
	*pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	openssl_cert_mkreq(&req, pkey, subject_name);

//	EC_KEY_print_fp(stdout, *pkey->pkey.ec_key, 0);

//	RSA_print_fp(stdout, pkey->pkey.rsa, 0);	//pkey.rsa changed with pkey.ec
//	X509_REQ_print_fp(stdout, req);
//	PEM_write_X509_REQ(stdout, req);

	/* Write Private Key to a file */
	if(!(fp = fopen(MY_KEY, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_KEY);
	if(PEM_write_PrivateKey(fp, *pkey, NULL, NULL, 0, NULL, NULL) != 1)
		fprintf(stderr, "Error while writing the RSA private key to file %s\n",MY_KEY);
	fclose(fp);

	/* Write X509_REQ to a file */
	if(!(fp = fopen(MY_REQ, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_REQ);
	if(PEM_write_X509_REQ(fp, req) != 1)
		fprintf(stderr, "Error while writing request to file %s", MY_REQ);
	fclose(fp);

	X509_REQ_free(req);
//	EVP_PKEY_free(pkey);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return(0);
}


/* Create PC1 */
int openssl_cert_create_pc1(EVP_PKEY **pkey, char *addr, unsigned char **subject_name) {

	char *filename;
	FILE *fp;
	X509 *pc0 = NULL, *pc1 = NULL;
	X509_REQ *req = NULL;
	BIO *bio_err;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

	/* Read the X509_REQ received */
	filename = (char *) malloc(255);
	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s", RECV_REQ);
	strncat(filename, addr, sizeof(filename)-strlen(filename)-1);
	if(!(fp = fopen(filename, "r")))
		fprintf(stderr, "Error opening file %s for reading!\n",filename);
	if(!(req = PEM_read_X509_REQ(fp, NULL, NULL, NULL)))
			fprintf(stderr, "Error while reading request from file %s", filename);
	fclose(fp);
	free(filename);


	/* Read the SP's PC0  */
	if(!(fp = fopen(MY_CERT, "r")))
		fprintf(stderr, "Error opening file %s for reading!\n",MY_CERT);
	if(!(pc0 = PEM_read_X509(fp, NULL, NULL, NULL)))
			fprintf(stderr, "Error while reading request from file %s", RECV_REQ);
	fclose(fp);


	if(openssl_cert_mkcert(pkey, req, &pc1, &pc0, subject_name) == 0) {

//		X509_print_fp(stdout,pc1);
//		PEM_write_X509(stdout,pc1);

		/* Write issued X509 PC1 to a file */
		if(!(fp = fopen(ISSUED_CERT, "w")))
			fprintf(stderr, "Error opening file %s for writing!\n",ISSUED_CERT);
		if(PEM_write_X509(fp, pc1) != 1)
			fprintf(stderr, "Error while writing request to file %s", ISSUED_CERT);
		fclose(fp);
		X509_free(pc1);
	}


#ifdef CUSTOM_EXT
	/* Only needed if we add objects or custom extensions */
	X509V3_EXT_cleanup();
	OBJ_cleanup();
#endif


	X509_free(pc0);

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);

}

int openssl_cert_read(in_addr addr, unsigned char **s, EVP_PKEY **p) {
	char *filename, *recv_addr_string;
	unsigned char *subject_name;
	EVP_PKEY *pub_key;
	X509 *cert;
	FILE *fp;

	if(*s == NULL || s == NULL) {
		subject_name = malloc(FULL_SUB_NM_SZ);
	} else {
		subject_name = *s;
	}

//	if(*p == NULL || p == NULL) {
//		pub_key = EVP_PKEY_new();
//	} else {
//		pub_key = *p;
//	}


	if(addr.s_addr == 0) {

		if(!(fp = fopen(SP_CERT, "r"))) {
			fprintf(stderr, "Error opening file %s for reading!\n", SP_CERT);
			return 0;
		}

	} else {

		filename = malloc(255);
		memset(filename, 0, sizeof(filename));
		sprintf(filename, "%s", RECV_CERT);
		recv_addr_string = inet_ntoa(addr);
		strncat(filename, recv_addr_string, sizeof(filename)-strlen(filename)-1);

		if(!(fp = fopen(filename, "r"))) {
			fprintf(stderr, "Error opening file %s for reading!\n", filename);
			return 0;
		}

		free(filename);

	}



	if(!(cert = PEM_read_X509(fp, NULL, NULL, NULL)))
			fprintf(stderr, "Error while reading certificate from file\n");
	fclose(fp);

	if(addr.s_addr != 0) {
		if(!X509_verify(cert, authenticated_list[0]->pub_key)) {
			printf("Could not verify certificate\n");
			return 0;
		}
	}


	pub_key = X509_get_pubkey(cert);
	X509_NAME_oneline(X509_get_subject_name(cert),(char *)subject_name, FULL_SUB_NM_SZ);

//	free(recv_addr_string);

	//TODO: This must be free'd, but not before the EVP_PKEY object that is free'd outside this function, maybe dereference and free outside this func??
//	X509_free(cert);

	*p = pub_key;
	*s = subject_name;

	return 1;
}



/* Send PC Handshake Invite */
void auth_invite_send(sockaddr_in *sin_dest) {

	printf("Sending INVITE message to new node\n");
	char *buf;
	char *ptr;
	am_packet *header;
	int packet_len;
	FILE *fp;

	header = (am_packet *) malloc(sizeof(am_packet));
	header->id = my_id;
	header->type = AUTH_INVITE;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, header, sizeof(am_packet));

	ptr = buf;
	ptr += sizeof(am_packet);

	packet_len = sizeof(am_packet);
	if(!(fp = fopen(MY_CERT, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",MY_CERT);

	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

	sendto(am_send_socket, buf, packet_len, 0, (struct sockaddr *)sin_dest, sizeof(struct sockaddr_in));

	free(buf);
	free(header);

}

/* Send PC Request */
void auth_request_send(sockaddr_in *sin_dest) {

	printf("Sending PC REQUEST to SP\n");
	am_packet *header;
	char *buf, *ptr;
	FILE *fp;
	int packet_len;

	header = (am_packet *) malloc(sizeof(am_packet));
	header->id = my_id;
	header->type = AUTH_REQ;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, header, sizeof(am_packet));
	ptr = buf;
	ptr += sizeof(am_packet);

	packet_len = sizeof(am_packet);
	if(!(fp = fopen(MY_REQ, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",MY_REQ);

	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

	sendto(am_send_socket, buf, packet_len, 0, (struct sockaddr *)sin_dest, sizeof(struct sockaddr_in));

	free(header);
	free(buf);

}

/* Send the issued PC1 */
void auth_issue_send(sockaddr_in *sin_dest) {

	printf("Sending/Issuing PC to new node\n");
	char *buf, *ptr;
	am_packet *am_header;
	int packet_len;
	FILE *fp;

	am_header = (am_packet *) malloc(sizeof(am_packet));
	am_header->id = my_id;
	am_header->type = AUTH_ISSUE;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, am_header, sizeof(am_packet));

	ptr = buf;
	ptr += sizeof(am_packet);

	packet_len = sizeof(am_packet);
	if(!(fp = fopen(ISSUED_CERT, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",ISSUED_CERT);

	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

	sendto(am_send_socket, buf, packet_len, 0, (struct sockaddr *)sin_dest, sizeof(struct sockaddr_in));

	free(am_header);
	free(buf);
}

void neigh_req_pc_send(sockaddr_in *neigh_addr) {

	printf("Requesting PC and sending my own PC to new neighbor\n");
	char *buf, *ptr;
	am_packet *am_header;
	int packet_len;
	FILE *fp;
//	sockaddr_in *neigh_addr;

	am_header = (am_packet *) malloc(sizeof(am_packet));
	am_header->id = my_id;
	am_header->type = NEIGH_PC_REQ;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, am_header, sizeof(am_packet));

	ptr = buf;
	ptr += sizeof(am_packet);

	packet_len = sizeof(am_packet);
	if(!(fp = fopen(MY_CERT, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",MY_CERT);

	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

//	neigh_addr = malloc(sizeof(sockaddr_in));
//	neigh_addr->sin_addr.s_addr = new_neighbor;
//	neigh_addr->sin_family = AF_INET;
//	neigh_addr->sin_port = htons(AM_PORT);

	sendto(am_send_socket, buf, packet_len, 0, (sockaddr *)neigh_addr, sizeof(sockaddr_in));

//	free(neigh_addr);
	free(am_header);
	free(buf);
}


/* Send my PC to new neighbor */
void neigh_pc_send(sockaddr_in *sin_dest) {

	printf("Sending my PC to a new neighbor\n");
	char *buf;
	am_packet *am_header;
	char *ptr;
	int packet_len;
	FILE *fp;

	am_header = (am_packet *) malloc(sizeof(am_packet));
	am_header->id = my_id;
	am_header->type = NEIGH_PC;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, am_header, sizeof(am_packet));

	ptr = buf;
	ptr += sizeof(am_packet);

	packet_len = sizeof(am_packet);
	if(!(fp = fopen(MY_CERT, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",MY_CERT);

	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

	sendto(am_send_socket, buf, packet_len, 0, (struct sockaddr *)sin_dest, sizeof(struct sockaddr_in));

	free(am_header);
	free(buf);
}

/* "Broadcast" Signed RAND Auth Packet to neighbors */
char *all_sign_send(EVP_PKEY *pkey, EVP_CIPHER_CTX *master, int *key_count) {

	printf("Broadcast new SIGN message to all neighbors\n");

	my_state = SENDING_NEW_SIGS;

	char *buf, *ptr, *keylen_ptr;
	unsigned char *current_iv = NULL, *current_rand = NULL;
	int i;
	am_packet *header;
	int value_len = RAND_LEN;
	int packet_len;
	routing_auth_packet *auth_header;

	unsigned int signature_len = (unsigned int)EVP_PKEY_size(pkey);

	/* First Generate New Current Key & IV */
	*key_count = *key_count + 1;
	if(current_key != NULL)
		free(current_key);
	current_key = openssl_key_generate(master, *key_count);
	openssl_key_iv_select(&current_iv, AES_IV_SIZE);


	/* Generate New RAND */
	openssl_tool_gen_rand(&current_rand, RAND_LEN);

	/* Sign Payload */
	unsigned char *signature_buffer = NULL;
	EVP_MD_CTX *md_ctx;

	md_ctx = EVP_MD_CTX_create();

	if(pkey->type == EVP_PKEY_RSA)
		EVP_SignInit(md_ctx, EVP_sha1());
	else if(pkey->type == EVP_PKEY_EC)
		EVP_SignInit(md_ctx, EVP_ecdsa());
	else {
		printf("Could not recognize Public Key Algorithm\n");
		return NULL;
	}


	EVP_SignUpdate(md_ctx, current_key, AES_KEY_SIZE);
	EVP_SignUpdate(md_ctx, current_iv, AES_IV_SIZE);
	EVP_SignUpdate(md_ctx, current_rand, RAND_LEN);

	signature_buffer = malloc(signature_len);

	if( EVP_SignFinal(md_ctx, signature_buffer, &signature_len, pkey) != 1) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(md_ctx);
		return NULL;
	}
	EVP_MD_CTX_destroy(md_ctx);


	/* Create Base64 encodings of payload */
	char *b64_iv 	= tool_base64_encode(current_iv, AES_IV_SIZE);
	char *b64_rand 	= tool_base64_encode(current_rand, RAND_LEN);
	char *b64_sign	= tool_base64_encode(signature_buffer, signature_len);

	/* Send Payload & Signature */
	header = (am_packet *) malloc(sizeof(am_packet));
	header->id = my_id;
	header->type = SIGNATURE;

	auth_header = malloc(sizeof(routing_auth_packet));
	auth_header->iv_len = strlen(b64_iv);
	auth_header->rand_len = strlen(b64_rand);
	auth_header->sign_len = strlen(b64_sign);


	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, header, sizeof(am_packet));
	ptr = buf;
	ptr += sizeof(am_packet);
	memcpy(ptr, auth_header, sizeof(routing_auth_packet));
	ptr += sizeof(routing_auth_packet);
	memcpy(ptr, b64_rand, strlen(b64_rand));
	ptr += strlen(b64_rand);
	memcpy(ptr, b64_iv, strlen(b64_iv));
	ptr += strlen(b64_iv);
	memcpy(ptr, b64_sign, strlen(b64_sign));
	ptr += strlen(b64_sign);


	sockaddr_in *tmp_dest = malloc(sizeof(sockaddr_in));
	tmp_dest->sin_family = AF_INET;
	tmp_dest->sin_port = htons(AM_PORT);
	for(i=0; i<num_trusted_neigh; i++) {

		tmp_dest->sin_addr.s_addr = neigh_list[i]->addr;

		/* Encrypt auth_packet with neighs public key */
		int j;
		for(j=0; j<num_auth_nodes; j++) {

			if(neigh_list[i]->id == authenticated_list[j]->id) {

				/* NEW ECC */

//				EC_KEY *ephemeral = NULL, *recip_pubkey = NULL;
//				const EC_GROUP *group = NULL;
//				size_t envelope_length, block_length, key_length;
//				unsigned char envelope_key[SHA256_DIGEST_LENGTH] = { 0 };
//				unsigned char iv[AES_IV_SIZE] = { 0 };
//				unsigned char block[EVP_MAX_BLOCK_LENGTH] = { 0 };
//
//				if ((key_length = EVP_CIPHER_key_length(ECDH_CIPHER)) * 2 > SHA256_DIGEST_LENGTH) {
//					printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. {envelope = %i / required = %zu}", SHA256_DIGEST_LENGTH / 8, (key_length * 2) / 8);
//					return NULL;
//				}
//
//				// Create the ephemeral key used specifically for this block of data.
//				if (!(ephemeral = EC_KEY_new())) {
//					printf("EC_KEY_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					return NULL;
//				}
//
//				//Extract Public key from AL and copy group settings
//				recip_pubkey = EVP_PKEY_get1_EC_KEY(authenticated_list[j]->pub_key);
//				group = EC_KEY_get0_group(recip_pubkey);
//
//
//				if (EC_KEY_set_group(ephemeral, group) != 1) {
//					printf("EC_KEY_set_group failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_GROUP_free(group);
//					EC_KEY_free(ephemeral);
//					return NULL;
//				}
//
//				EC_GROUP_free(group);
//
//				if (EC_KEY_generate_key(ephemeral) != 1) {
//					printf("EC_KEY_generate_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					return NULL;
//				}
//
//
//				// Use the intersection of the provided keys to generate the envelope data used by the ciphers below. The ecies_key_derivation() function uses
//				// SHA 256 to ensure we have a sufficient amount of envelope key material and that the material created is sufficiently secure.
//				if (ECDH_compute_key(envelope_key, SHA256_DIGEST_LENGTH, EC_KEY_get0_public_key(recip_pubkey), ephemeral, KDF1_SHA256) != SHA256_DIGEST_LENGTH) {
//					printf("An error occurred while trying to compute the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//				// Determine the envelope and block lengths so we can allocate a buffer for the result.
//				if ((block_length = EVP_CIPHER_block_size(ECDH_CIPHER)) == 0 || block_length > EVP_MAX_BLOCK_LENGTH ||
//						(envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral), POINT_CONVERSION_COMPRESSED, NULL, 0, NULL)) == 0) {
//
//					printf("Invalid block or envelope length. {block = %zu / envelope = %zu}\n", block_length, envelope_length);
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//
//				secure_t *cryptex;
//
//				// We use a conditional to pad the length if the input buffer is not evenly divisible by the block size.
//				if (!(cryptex = secure_alloc(envelope_length, EVP_MD_size(ECDH_HASHER), AES_KEY_SIZE, AES_KEY_SIZE + (AES_KEY_SIZE % block_length ? (block_length - (AES_KEY_SIZE % block_length)) : 0)))) {
//					printf("Unable to allocate a secure_t buffer to hold the encrypted result.\n");
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					return NULL;
//				}
//
//
//				// Store the public key portion of the ephemeral key.
//				if (EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral), POINT_CONVERSION_COMPRESSED, (char *)cryptex+sizeof(secure_head_t), envelope_length, NULL) != envelope_length) {
//					printf("An error occurred while trying to record the public portion of the envelope key. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EC_KEY_free(ephemeral);
//					EC_KEY_free(recip_pubkey);
//					free(cryptex);
//					return NULL;
//				}
//
//				// The envelope key has been stored so we no longer need to keep the keys around.
//				EC_KEY_free(ephemeral);
//				EC_KEY_free(recip_pubkey);
//
//				// For now we use an empty initialization vector.
//				memset(iv, 0, AES_IV_SIZE);
////				RAND_pseudo_bytes(&iv, AES_IV_SIZE);
//
//				// Setup the cipher context, the body length, and store a pointer to the body buffer location.
//				EVP_CIPHER_CTX cipher;
//				void *body;
//				int body_length;
//
//				EVP_CIPHER_CTX_init(&cipher);
//				body = secure_body_data(cryptex);
//				body_length = ((secure_head_t *)cryptex)->length.body;
//
//
//				// Initialize the cipher with the envelope key.
//				if (EVP_EncryptInit_ex(&cipher, ECDH_CIPHER, NULL, envelope_key, iv) != 1 ||
//						EVP_CIPHER_CTX_set_padding(&cipher, 0) != 1 ||
//						EVP_EncryptUpdate(&cipher, body, &body_length, current_key,
//								AES_KEY_SIZE - (AES_KEY_SIZE % block_length)) != 1)
//				{
//
//					printf("An error occurred while trying to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//
//				}
//
//
//				// Advance the pointer, then use pointer arithmetic to calculate how much of the body buffer has been used. The complex logic is needed so that we get
//				// the correct status regardless of whether there was a partial data block.
//				body += body_length;
//				if ((body_length = ((secure_head_t *)cryptex)->length.body - (body - secure_body_data(cryptex))) < 0) {
//					printf("The symmetric cipher overflowed!\n");
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//				}
//
//
//				if (EVP_EncryptFinal_ex(&cipher, body, &body_length) != 1) {
//					printf("Unable to secure the data using the chosen symmetric cipher. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//					EVP_CIPHER_CTX_cleanup(&cipher);
//					free(cryptex);
//					return NULL;
//				}
//
//				EVP_CIPHER_CTX_cleanup(&cipher);
//
//				// Generate an authenticated hash which can be used to validate the data during decryption.
//				HMAC_CTX hmac;
//				unsigned int mac_length;	mac_value = ;
//				HMAC_CTX_init(&hmac);
//				mac_length = ((secure_head_t *)cryptex)->length.mac;
//
//				// At the moment we are generating the hash using encrypted data. At some point we may want to validate the original text instead.
//				HMAC_Init_ex(&hmac, envelope_key + key_length, key_length, ECDH_HASHER, NULL);
//				HMAC_Update(&hmac, current_key, AES_KEY_SIZE);
//				HMAC_Final(&hmac, secure_mac_data(cryptex), &mac_length);
////				{
////
////					printf("Unable to generate a data authentication code. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
////					HMAC_CTX_cleanup(&hmac);
////					free(cryptex);
////					return NULL;
////				}
//
//				HMAC_CTX_cleanup(&hmac);
//
//				tool_dump_memory((unsigned char *)secure_body_data(cryptex), body_length);
//
//				printf("\n\nICH BIN HIER!\n\n");
//				exit(1);



				/* OLD ECC */

//				recip_pubkey = EVP_PKEY_get1_EC_KEY(authenticated_list[j]->pub_key);
//				group = EC_KEY_get0_group(recip_pubkey);
//
//				ephemeral_key = EC_KEY_new();
//				EC_KEY_set_group(ephemeral_key, group);
//
//				EC_KEY_generate_key(ephemeral_key);
//
//				// With this 256 bit long buffer, we have a 128bit (16 Byte) AES key and IV to encrypt the key being sent...
//				ECDH_compute_key(key_iv_buf, sizeof key_iv_buf, EC_KEY_get0_public_key(recip_pubkey), ephemeral_key, KDF1_SHA256);
//				unsigned char *key, *iv;
//				key = malloc(AES_KEY_SIZE);
//				iv = malloc(AES_IV_SIZE);
//				memcpy(key, key_iv_buf, AES_KEY_SIZE);
//				memcpy(iv, key_iv_buf+AES_KEY_SIZE, AES_IV_SIZE);
//
//				EVP_CIPHER_CTX aes_ctx;
//				EVP_EncryptInit(&aes_ctx, EVP_aes_128_ecb(), key, iv);
//				unsigned char *encrypted_key;
//				int encrypted_key_len = AES_KEY_SIZE;
//				encrypted_key = openssl_aes_encrypt(&aes_ctx, current_key, &encrypted_key_len);
//
//				free(key);
//				free(iv);
//

				RSA *neig_rsa = authenticated_list[j]->pub_key->pkey.rsa;

				unsigned char *encrypted_key = malloc(RSA_size(neig_rsa));
				if(RSA_public_encrypt(AES_KEY_SIZE, current_key, encrypted_key, neig_rsa, RSA_PKCS1_OAEP_PADDING) == -1) {
					printf("Error while encrypting with neigbhbors public key\n");
					break;
				}

				char *b64_key = tool_base64_encode(encrypted_key, RSA_size(neig_rsa));



				/* Put packet together in buffer */
				memset(ptr, 0 , buf+MAXBUFLEN-ptr);
				memcpy(ptr, b64_key, strlen(b64_key));

				packet_len = (ptr + strlen(b64_key)) - buf;

				/* Send packet to neigh */
				sendto(am_send_socket, buf, packet_len, 0, (sockaddr *)tmp_dest, sizeof(sockaddr_in));

				/* Free */
				free(encrypted_key);
				free(b64_key);

				//Go out of last for-loop, but continue with first loop to find next neighbor
				break;

			}
		}

	}



	/* Generate Keystream from Nonce */

	if(*key_count>1)
		free(auth_value);

	int rand_len = RAND_LEN;
	auth_value = malloc(rand_len*10+10);
	auth_value_len = 0;

	for(i=0; i<10; i++) {

		/* Do encryption */
		EVP_CIPHER_CTX current_ctx;
		EVP_EncryptInit(&current_ctx, EVP_aes_128_cbc(), current_key, current_iv);
		unsigned char *tmp = openssl_aes_encrypt(&current_ctx, current_rand, &value_len);
		EVP_CIPHER_CTX_cleanup(&current_ctx);

		/* Place ciphertext in keystream */
		int auth_pos = auth_value_len;
		auth_value_len += value_len;
		memcpy(auth_value+auth_pos, tmp, value_len);

		/* Change to new IV */
		memcpy(current_iv, tmp, AES_IV_SIZE);

		/* Alter the Nonce before next encryption */
		int j;
		for(j=0;j<rand_len/10; j++) {
			current_rand[j+(i*(rand_len/10))] = ( (current_rand[j+(i*(rand_len/10))]) ^ i );
//			printf("index : %d\n", j+(i*(rand_len/10)));
		}
//		tool_dump_memory(current_rand, RAND_LEN);

		free(tmp);
		value_len = RAND_LEN;

	}

//	tool_dump_memory(auth_value, auth_value_len);
	auth_seq_num = 0;




	/* Free up stuff */
	memset(ptr, 0 , buf+MAXBUFLEN-ptr);
	free(tmp_dest);
	free(header);
	free(auth_header);
	free(current_iv);
	memset(current_rand, 0, RAND_LEN);
	free(current_rand);
	free(b64_iv);
	free(b64_rand);
	free(b64_sign);
	free(signature_buffer);
	my_state = READY;
	last_send_time = time (NULL);
	return buf;
}


/* Send Signed RAND Auth Packet to new neighbor */
void neigh_sign_send(EVP_PKEY *pkey, sockaddr_in *addr, char *buf) {

	char *addr_char = malloc(16);
	inet_ntop( AF_INET, &(addr->sin_addr.s_addr), addr_char, 16 );
	printf("Send SIGN message to neighbor - %s\n", addr_char);
	free(addr_char);
printf("1\n");
	char *payload_ptr,* key_ptr;

	payload_ptr = buf + sizeof(am_packet) + sizeof(routing_auth_packet);
	key_ptr = payload_ptr + strlen(payload_ptr);
printf("2\n");
	/* Encrypt auth_packet with neighs public key */
	int j;
	for(j=0; j<num_auth_nodes; j++) {
printf("3\n");
		if(addr->sin_addr.s_addr == authenticated_list[j]->addr) {
printf("4\n");
			RSA *neig_rsa = authenticated_list[j]->pub_key->pkey.rsa;
printf("5\n");
			unsigned char *encrypted_key = malloc(RSA_size(neig_rsa));
printf("6\n");
			if(RSA_public_encrypt(AES_KEY_SIZE, current_key, encrypted_key, neig_rsa, RSA_PKCS1_OAEP_PADDING) == -1) {
				printf("Error while encrypting with neigbhbors public key\n");
				break;
			}
printf("7\n");
			char *b64_key 	= tool_base64_encode(encrypted_key, RSA_size(neig_rsa));
printf("8\n");

			/* Put packet together in buffer */
			memcpy(key_ptr, b64_key, strlen(b64_key));
			int packet_len = sizeof(am_packet) + sizeof(routing_auth_packet) + strlen(payload_ptr);
printf("9\n");
			sendto(am_send_socket, buf, packet_len, 0, (sockaddr *)addr, sizeof(sockaddr_in));
printf("10\n");
			memset(key_ptr, 0 , buf+MAXBUFLEN-key_ptr);

			free(encrypted_key);
			free(b64_key);
			break;
printf("func end\n");
		}
	}
}


/* Extract AM Data Type From Received AM Packet */
am_type am_header_extract(char *buf, char **ptr, int *id) {

	am_packet *header;
	header = (am_packet *)buf;

	*ptr = buf;
	*ptr += sizeof(am_packet);

	*id = header->id;

	return header->type;

}

/* Receive Invite */
int auth_invite_recv(char *ptr) {

	printf("Received INVITE message\n");

	FILE *fp;

	if(!(fp = fopen(SP_CERT, "w"))) {
		fprintf(stderr, "Error opening file %s for writing!\n", SP_CERT);
		return 0;
	}

	fwrite(ptr, 1, strlen(ptr), fp);
	fclose(fp);
	return 1;
}

/* Receive Routing Auth Packet */
int neigh_sign_recv(EVP_PKEY *pkey, uint32_t addr, uint16_t id, char *ptr) {

	char *addr_char = malloc(16);
	inet_ntop( AF_INET, &addr, addr_char, 16 );
	printf("Receive SIGN message from neighbor - %s\n", addr_char);
	free(addr_char);

	routing_auth_packet *auth_header = (routing_auth_packet *)ptr;
	ptr = ptr + sizeof(routing_auth_packet);

	/* Decode Base64 variables */
	unsigned char *randval, *iv, *sign, *encrypted_key;
	int rand_len, iv_len, sign_len, encrypted_key_len;

	randval = tool_base64_decode(ptr, auth_header->rand_len, &rand_len);
	iv = tool_base64_decode(ptr + auth_header->rand_len, auth_header->iv_len, &iv_len);
	sign = tool_base64_decode(ptr + auth_header->rand_len + auth_header->iv_len, auth_header->sign_len, &sign_len);
	int tmp = strlen(ptr) - (auth_header->rand_len + auth_header->iv_len + auth_header->sign_len);
	encrypted_key = tool_base64_decode(ptr + auth_header->rand_len + auth_header->iv_len + auth_header->sign_len, tmp, &encrypted_key_len);


	unsigned char *key = NULL;
	int key_len;
	int i;
	for(i=0; i<num_auth_nodes; i++) {
		if(authenticated_list[i]->id == id) {

			/* Decrypt key */
			key = malloc(AES_KEY_SIZE);
			RSA_private_decrypt(encrypted_key_len, encrypted_key, key, pkey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
			key_len = AES_KEY_SIZE;


			/* Verify Signature */
			EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

			if (authenticated_list[i]->pub_key->type ==  EVP_PKEY_RSA)
				EVP_VerifyInit(md_ctx, EVP_sha1());
			else if (authenticated_list[i]->pub_key->type ==  EVP_PKEY_EC)
				EVP_VerifyInit(md_ctx, EVP_ecdsa());
			else {
				printf("Unknown Public Key Algorithm\n");
				return 0;
			}

			EVP_VerifyUpdate(md_ctx, key, key_len);
			EVP_VerifyUpdate(md_ctx, iv, iv_len);
			EVP_VerifyUpdate(md_ctx, randval, rand_len);

			if(EVP_VerifyFinal(md_ctx,sign, sign_len, authenticated_list[i]->pub_key) != 1) {
				ERR_print_errors_fp(stderr);
				EVP_MD_CTX_destroy(md_ctx);
				return 0;
			}

			EVP_MD_CTX_destroy(md_ctx);
			break;
		}
	}

	if(i == num_auth_nodes) {
		printf("Could not find node in AL\n");
		return 0;
	}







	//	printf("\nTrying to verify signature with this public key:\n");
	//	PEM_write_PUBKEY(stdout,authenticated_list[i]->pub_key);
	//
	//	printf("\nKEY:\n");
	//	tool_dump_memory(key, key_len);
	//
	//	printf("\nIV:\n");
	//	tool_dump_memory(iv, iv_len);
	//
	//	printf("\nRAND:\n");
	//	tool_dump_memory(randval, rand_len);
	//
	//	printf("\n Checking againts this SIGN:\n");
	//	tool_dump_memory(sign, sign_len);



	unsigned char *mac_value = malloc(rand_len*10+10);
	int mac_value_len = RAND_LEN;

	rand_len = RAND_LEN;
	auth_value_len = 0;

	for(i=0; i<10; i++) {

		/* Do encryption */
		EVP_CIPHER_CTX received_ctx;
		EVP_EncryptInit(&received_ctx, EVP_aes_128_cbc(), key, iv);
		unsigned char *tmp = openssl_aes_encrypt(&received_ctx, randval, &mac_value_len);
		EVP_CIPHER_CTX_cleanup(&received_ctx);

		/* Place ciphertext in keystream */
		int auth_pos = auth_value_len;
		auth_value_len += mac_value_len;
		memcpy(mac_value+auth_pos, tmp, mac_value_len);

		/* Change to new IV */
		memcpy(iv, tmp, AES_IV_SIZE);

		/* Alter the Nonce before next encryption */
		int j;
		for(j=0;j<rand_len/10; j++) {
			randval[j+(i*(rand_len/10))] = ( (randval[j+(i*(rand_len/10))]) ^ i );
//			printf("index : %d\n", j+(i*(rand_len/10)));
		}
//		tool_dump_memory(current_rand, RAND_LEN);

		free(tmp);
		mac_value_len = RAND_LEN;

	}

//	tool_dump_memory(mac_value, auth_value_len);

	neigh_list_add(addr, id, mac_value);

	if(my_state == WAIT_FOR_NEIGH_SIG)
		my_state = READY;

	free(encrypted_key);
	free(key);
	free(iv);
	free(randval);
	free(sign);
	return 1;

}

/* Receive PC request along with the PC of a new neighbor */
int neigh_pc_recv(in_addr addr, char *ptr) {

	printf("Received PC from a new neighbor\n");
	char *filename, *recv_addr_string;
	FILE *fp;

	filename = malloc(255);
	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s", RECV_CERT);

//	recv_addr_string = malloc(16);
	recv_addr_string = inet_ntoa(addr);
//	memcpy(recv_addr_string, inet_ntoa(addr), sizeof(recv_addr_string));
	strncat(filename, recv_addr_string, sizeof(filename)-strlen(filename)-1);

	if(!(fp = fopen(filename, "w"))) {
		fprintf(stderr, "Error opening file %s for writing!\n", filename);
		return 0;
	}
	fwrite(ptr, 1, strlen(ptr), fp);

	fclose(fp);
//	free(recv_addr_string);
	free(filename);
	return 1;
}

/* Receive PC Request */
int auth_request_recv(char *addr, char *ptr) {
	printf("Received a PC REQUEST from new node\n");
	char *filename;
	FILE *fp;

	filename = (char *) malloc(255);
	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s", RECV_REQ);
	strncat(filename, addr, sizeof(filename)-strlen(filename)-1);

	if(!(fp = fopen(filename, "w"))) {
		fprintf(stderr, "Error opening file %s for writing!\n", filename);
		return 0;
	}

	fwrite(ptr, 1, strlen(ptr), fp);
	fclose(fp);
	free(filename);
	return 1;

}

/* Receive PC Issue */
int auth_issue_recv(char *ptr) {

	printf("Received PC from SP\n");
	FILE *fp;

	if(!(fp = fopen(MY_CERT, "w"))) {
		fprintf(stderr, "Error opening file %s for writing!\n", MY_CERT);
		return 0;
	}

	fwrite(ptr, 1, strlen(ptr), fp);
	fclose(fp);
	return 1;
}







/* Socket abstraction functions */

void socks_am_setup(int32_t *recvsock, int32_t *sendsock) {

	addrinfo hints, *res;

	/* Set family information */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;

	/* Set port number to addrinfo object */
	char *port;
	port = (char *) malloc(6);
	sprintf(port, "%d", AM_PORT);

	getaddrinfo(NULL, port, &hints, &res);

	free(port);

	/* Setup Receive and Send Sockets */
	if(!socks_recv_setup(recvsock, res) || !socks_send_setup(sendsock))
		socks_am_destroy(sendsock, recvsock);

	free(res);
}

int socks_recv_setup(int32_t *recvsock, addrinfo *res) {

	/* Assign file descriptor for socket */
	if ( (*recvsock = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		printf("Error - can't create AM receive socket: %s\n", strerror(errno) );
		return 0;
	}

	/* Binds the socket to the network interface as given by Batman */
	if(setsockopt(*recvsock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) == -1) {
		printf("Could not bind recv socket to device %s!\n", interface);
		exit(0);
	}

	/* Binds socket to the port (rest of the address is empty/null) */
	bind(*recvsock, res->ai_addr, res->ai_addrlen);

	return 1;
}

int socks_send_setup(int32_t *sendsock) {

	/* Assign file descriptor for socket */
	if ( (*sendsock = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		printf("Error - can't create AM send socket: %s\n", strerror(errno) );
		return 0;
	}

	/* Binds the socket to the network interface as given by Batman */
	if(setsockopt(*sendsock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) == -1) {
		printf("Could not bind send socket to device %s!\n", interface);
		exit(0);
	}

	/* Allow this socket to send broadcast messages */
	int broadcast_val = 1;
	if(setsockopt(*sendsock, SOL_SOCKET, SO_BROADCAST, &broadcast_val, sizeof(broadcast_val)) == -1) {
		printf("Could not bind send socket to device %s!\n", interface);
		exit(0);
	}

	/* Sets the socket to non-blocking */
	fcntl(*sendsock, F_SETFL, O_NONBLOCK);

	return 1;
}

void socks_am_destroy(int32_t *send, int32_t *recv) {

	printf("WARNING: Destroying AM Sockets!\n");
	if (*recv != 0)
		close(*recv);
	if (*send != 0)
		close(*send);
	*recv = 0;
	*send = 0;
}




/* BASE 64 */

/* Encode to Base64 */
char *tool_base64_encode(unsigned char * input, int length) {

    BIO *b64 = NULL;
    BIO * bmem = NULL;
    BUF_MEM *bptr = NULL;
    char * output = NULL;

    b64 = BIO_new((BIO_METHOD *)BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    output = (char *) calloc (bptr->length + 1, sizeof(char));
    memcpy(output, bptr->data, bptr->length);

    BIO_free_all(b64);

    return output;
}

/* Decode from Base64 */
unsigned char *tool_base64_decode(char * input, int in_length, int *out_length) {

	  BIO *b64, *bmem;

	  char *output = (char *)malloc(in_length);
	  memset(output, 0, in_length);

	  b64 = BIO_new(BIO_f_base64());
	  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	  bmem = BIO_new_mem_buf(input, in_length);
	  bmem = BIO_push(b64, bmem);

	  *out_length = BIO_read(bmem, output, in_length);

	  BIO_free_all(bmem);

	  unsigned char *retval = malloc(*out_length);
	  memcpy(retval, output, *out_length);
	  free(output);

	  return retval;

}


/* Certificate and Requests Creation Helper Functions */

/* PC0 Creation and Selfsigning */
int openssl_cert_selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char **subject_name) {
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
//	EC_KEY *ec_key;
//	EC_GROUP *ecgroup;
	X509_NAME *name=NULL;
	int bits = RSA_KEY_SIZE;


	if ((pkeyp == NULL) || (*pkeyp == NULL))
		{
		if ((pk=EVP_PKEY_new()) == NULL)
			{
			abort();
			return(0);
			}
		}
	else
		pk= *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL))
		{
		if ((x=X509_new()) == NULL)
			goto err;
		}
	else
		x= *x509p;



	rsa=RSA_generate_key(bits,RSA_F4,openssl_tool_callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		{
		abort();
		goto err;
		}
	rsa=NULL;

//	ec_key = EC_KEY_new();
//
//	if(ec_key == NULL) {
//		printf("Could not initiate ECC key!\n");
//		exit(1);
//	}
//
//	if (!(ecgroup = EC_GROUP_new_by_curve_name(ECC_CURVE))) {
//		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//	}
//
//
//	if (EC_GROUP_precompute_mult(ecgroup, NULL) != 1) {
//		printf("EC_GROUP_precompute_mult failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//		EC_GROUP_free(ecgroup);
//	}
//
//	EC_GROUP_set_point_conversion_form(ecgroup, POINT_CONVERSION_COMPRESSED);
//
//	if(EC_KEY_set_group(ec_key, ecgroup) != 1) {
//		printf("Failed to set group for EC Key\n");
//		exit(1);
//	}
//
//	if(EC_KEY_generate_key(ec_key) != 1) {
//		printf("Failed to generate EC Key\n");
//		exit(1);
//	}
//
//	EC_KEY_print_fp(stdout, ec_key, 0);
//
//	if(!EVP_PKEY_assign_EC_KEY(pk, ec_key)) {
//		printf("Failed to assign EC key to PKEY\n");
//		exit(1);
//	}

	if(X509_set_version(x,2L) != 1)
		fprintf(stderr,"Error setting certificate version");
	ASN1_INTEGER_set(X509_get_serialNumber(x),rand()%INT32_MAX);	//serial, change later to sha1 of public key
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*8);	//60 sec, 60 min, 8 hrs
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	sprintf((char *)*subject_name,"SP_%d",rand()%UINT32_MAX);
	X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, *subject_name, -1, -1, 0);

	X509_set_issuer_name(x,name);

#if 0
	/* Add extension using V3 code: we can set the config file as NULL
	 * because we wont reference any other sections. We can also set
         * the context to NULL because none of these extensions below will need
	 * to access it.
	 */

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
						"example comment extension");
	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name,
							"www.openssl.org");

	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);


	/* might want something like this too.... */
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
							"critical,CA:TRUE");


	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);
#endif

#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		ex = X509V3_EXT_conf_nid(NULL, NULL, nid,
						"example comment alias");
		X509_add_ext(x,ex,-1);
		X509_EXTENSION_free(ex);
	}
#endif

	if (!X509_sign(x,pk,EVP_sha1()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}


/* PC REQ Creation */
int openssl_cert_mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name) {
	X509_REQ *x;
	EVP_PKEY *pk;
	RSA *rsa;
//	EC_KEY *ec_key;
//	EC_GROUP *ecgroup;
	X509_NAME *name=NULL;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	int bits = RSA_KEY_SIZE;

	if ((pk=EVP_PKEY_new()) == NULL)
		goto err;

	if ((x=X509_REQ_new()) == NULL)
		goto err;

	rsa=RSA_generate_key(bits,RSA_F4,openssl_tool_callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		goto err;

	rsa=NULL;

//	ec_key = EC_KEY_new();
//
//	if(ec_key == NULL) {
//		printf("Could not initiate ECC key!\n");
//		exit(1);
//	}
//
//	if (!(ecgroup = EC_GROUP_new_by_curve_name(ECC_CURVE))) {
//		printf("EC_GROUP_new_by_curve_name failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//	}
//
//
//	if (EC_GROUP_precompute_mult(ecgroup, NULL) != 1) {
//		printf("EC_GROUP_precompute_mult failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
//		EC_GROUP_free(ecgroup);
//	}
//
//	EC_GROUP_set_point_conversion_form(ecgroup, POINT_CONVERSION_COMPRESSED);
//
//
//
//	if(EC_KEY_set_group(ec_key, ecgroup) != 1) {
//		printf("Failed to set group for EC Key\n");
//		exit(1);
//	}
//
//	if(EC_KEY_generate_key(ec_key) != 1) {
//		printf("Failed to generate EC Key\n");
//		exit(1);
//	}
//
//	EC_KEY_print_fp(stdout, ec_key, 0);
//
//	if(!EVP_PKEY_assign_EC_KEY(pk, ec_key)) {
//		printf("Failed to assign EC key to PKEY\n");
//		exit(1);
//	}

	X509_REQ_set_pubkey(x,pk);
	name=X509_REQ_get_subject_name(x);

	/*
	 * This is where we add the Subject (unique) Common Name.
	 * The Issuer name will be prepended by the issuer on creation.
	 * TODO: Maybe use hash of public key, for now only a random number
	 */
	subject_name = malloc(SUBJECT_NAME_SIZE);
	sprintf((char *)subject_name,"%d",rand()%UINT32_MAX);
	X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, subject_name, -1, -1, 0);
	free(subject_name);

//#ifdef REQUEST_EXTENSIONS
	/* Certificate requests can contain extensions, which can be used
	 * to indicate the extensions the requestor would like added to
	 * their certificate. CAs might ignore them however or even choke
	 * if they are present.
	 */

	/* For request extensions they are all packed in a single attribute.
	 * We save them in a STACK and add them all at once later...
	 */

	exts = sk_X509_EXTENSION_new_null();
	/* Standard extenions */

	if(req_role == AUTHENTICATED)
		openssl_cert_add_ext_req(exts, NID_netscape_comment, "critical,myProxyCertInfoExtension:0,1");
	else
		openssl_cert_add_ext_req(exts, NID_netscape_comment, "critical,myProxyCertInfoExtension:0,0");

//	char * pci_value = "critical, language:Inherit all";

//	X509_EXTENSION *ext =NULL;
//	ext = X509V3_EXT_conf(NULL, NULL, "proxyCertInfo", "critical,language:Inherit all");
//	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_proxyCertInfo, pci_value);

//	/* PROCYCERTINFO */
//
//	//Les http://root.cern.ch/svn/root/vendors/xrootd/current/src/XrdCrypto/XrdCryptosslgsiAux.cc
//
//	//Create ProxyPolicy
//    PROXYPOLICY *proxyPolicy;
//    proxyPolicy = NULL;
////    ASN1_CTX c; /* Function below needs this to be defined */
////    M_ASN1_New_Malloc(proxyPolicy, PROXYPOLICY);
//    proxyPolicy = (PROXYPOLICY *)OPENSSL_malloc(sizeof(PROXYPOLICY));
//    proxyPolicy->policy_language = OBJ_nid2obj(NID_id_ppl_inheritAll);
//    proxyPolicy->policy = NULL;
////    M_ASN1_New_Error(ASN1_F_PROXYPOLICY_NEW);
//
//    //Create ProxyCertInfo
//    PROXYCERTINFO *proxyCertInfo;
//    proxyCertInfo = NULL;
////    M_ASN1_New_Malloc(proxyCertInfo, PROXYCERTINFO);
//    proxyCertInfo = (PROXYCERTINFO *)OPENSSL_malloc(sizeof(PROXYCERTINFO));
//    memset(proxyCertInfo, (int) NULL, sizeof(PROXYCERTINFO));
//    proxyCertInfo->path_length = NULL;
//    proxyCertInfo->policy = proxyPolicy;
//
//
//    //Mucho try-as-i-go, need cleanup!!!
//    X509V3_CTX ctx;
//    X509V3_CONF_METHOD method = { NULL, NULL, NULL, NULL };
//    long db = 0;
//
//    char language[80];
//    int pathlen;
//    unsigned char *policy = NULL;
//    int policy_len;
//    char *value;
//    char *tmp;
//
//    ASN1_OCTET_STRING *             ext_data;
//    int                             length;
//    unsigned char *                 data;
//    unsigned char *                 der_data;
//    X509_EXTENSION *                proxyCertInfo_ext;
//    const X509V3_EXT_METHOD *       proxyCertInfo_ext_method;
//
//    proxyCertInfo_ext_method = X509V3_EXT_get_nid(NID_proxyCertInfo);

//    proxyCertInfo_ext_method = X509V3_EXT_get_nid(OBJ_txt2nid(PROXYCERTINFO_OLD_OID));
//
//
//
//    OBJ_obj2txt(language, 80, proxyCertInfo->policy->policy_language, 1);
//    sprintf(&language, "blablabla");
//    proxyCertInfo->policy->policy_language = OBJ_txt2obj(language, 1);
//
//    pathlen = 0;
//    ASN1_INTEGER_set(&(proxyCertInfo->path_length), (long)pathlen);
//
//    if (proxyCertInfo->policy->policy) {
//    	policy_len = M_ASN1_STRING_length(proxyCertInfo->policy->policy);
//    	policy = malloc(policy_len + 1);
//    	memcpy(policy, M_ASN1_STRING_data(proxyCertInfo->policy->policy), policy_len);
//    	policy[policy_len] = '\0';
//    }
//
//
//    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0L);
//    ctx.db_meth = &method;
//    ctx.db = &db;
//
//    pci_ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_proxyCertInfo, value);
//    X509_EXTENSION_set_critical(pci_ext, 1);
//
//    add_ext(exts, NID_proxyCertInfo, value);
//
//    if(proxyCertInfo_ext_method) {
//    	printf("\n\next_method\n\n\n");
//    }
//    if (proxyCertInfo_ext_method->i2v) {
//    	printf("\n\next_method->i2v\n\n\n");
//    }
//    if(proxyCertInfo_ext_method->v2i) {
//    	printf("\n\next_method->v2i\n\n\n");
//    }
//    if (proxyCertInfo_ext_method->i2r) {
//    	printf("\n\next_method->i2r\n\n\n");
//    }
//    if(proxyCertInfo_ext_method->r2i) {
//    	printf("\n\next_method->r2i\n\n\n");
//    }
//
//
//    printf("\n\nTEST\n\n\n");
//    proxyCertInfo_ext_method->i2d(proxyCertInfo, NULL);




#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_certificate_policies);
		openssl_cert_add_ext_req(x, nid, "example comment alias");
	}
#endif

	/* Now we've created the extensions we add them to the request */

	X509_REQ_add_extensions(x, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

//#endif

	if (!X509_REQ_sign(x,pk,EVP_sha1()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);

}


/* PC1 Creation */
int openssl_cert_mkcert(EVP_PKEY **pkey, X509_REQ *req,X509 **pc1p, X509 **pc0p, unsigned char **subject_name) {
	EVP_PKEY *req_pkey, *my_pkey;
	X509_NAME *name, *req_name, *issuer_name;
	X509_NAME_ENTRY *req_name_entry;
	X509  *cert;
	FILE *fp;

	/* Verify signature on REQ */
	if(!(req_pkey = X509_REQ_get_pubkey(req)))
		fprintf(stderr,"Error getting public key from request");
	if(X509_REQ_verify(req, req_pkey) != 1)
		fprintf(stderr,"Error verifying signature on certificate");

	/* Read my private key */
	if(!(fp = fopen(MY_KEY, "r")))
		fprintf(stderr, "Error opening file %s for reading!\n",RECV_REQ);
	if(!(my_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		fprintf(stderr,"Error reading private key of SP");
	fclose(fp);


	/* Read Subject Name of request */
	if(!(req_name = X509_REQ_get_subject_name(req)))
		fprintf(stderr,"Error getting subject name from request\n");

	/* Read Subject Name of PC0 */
	if(!(issuer_name = X509_get_subject_name(*pc0p)))
		fprintf(stderr,"Error getting subject name from request\n");


	/* Create new X509 (PC1) */
	if(!(cert = X509_new()))
		fprintf(stderr,"Error creating X509 object\n");


	/* Set version */
	if(X509_set_version(cert,2L) != 1)
		fprintf(stderr,"Error setting certificate version");

	/* Set serial number, change to relevant hash later */
	ASN1_INTEGER_set(X509_get_serialNumber(cert), rand()%INT32_MAX);

	/* Set issuer */
	if(X509_set_issuer_name(cert, issuer_name) != 1)
		fprintf(stderr,"Error setting the issuer name");

	/* Set subject name from issuer name */
	if((name = X509_NAME_dup(issuer_name)) == NULL)
		fprintf(stderr,"Error setting subject name from issuer name\n");

	/* Append subject request name to the subject name */
	req_name_entry = X509_NAME_get_entry(req_name,0);
	X509_NAME_add_entry(name, req_name_entry, X509_NAME_entry_count(name), 0);

	if(X509_set_subject_name(cert, name) != 1)
		fprintf(stderr,"Error setting the subject name to the certificate\n");

	X509_NAME_free(name);
	X509_NAME_ENTRY_free(req_name_entry);

	X509_NAME_oneline(X509_get_subject_name(cert),(char *)*subject_name, FULL_SUB_NM_SZ);


	/* Set public key */
	if(X509_set_pubkey(cert, req_pkey) != 1)
		fprintf(stderr,"Error setting the public key to the certificate\n");

	/* Set lifetime of cert */
	if(!(X509_gmtime_adj(X509_get_notBefore(cert), 0)))
		fprintf(stderr,"Error setting the start lifetime of cert");
	if(!(X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*8)))
		fprintf(stderr,"Error setting the end lifetime of cert");

	/* Get and set proxypolicy */
	STACK_OF(X509_EXTENSION) *req_exts = X509_REQ_get_extensions(req);
//	X509_EXTENSION *ex;
//	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
//	if (!ex)
//		return 0;
	if (req_exts != NULL) {
		int num_exts = sk_X509_EXTENSION_num(req_exts);
		X509_EXTENSION *req_ex = NULL;
		req_ex = sk_X509_EXTENSION_pop(req_exts);
//		openssl_cert_add_ext_req(exts, NID_netscape_comment, "critical,myProxyCertInfoExtension:0,0");
//		const unsigned char *req_value;
//		d2i_ASN1_OCTET_STRING(&(req_ex->value), &req_value, req_ex->value->length);

//		STACK_OF(X509_EXTENSION) *exts = NULL;
//		sk_X509_EXTENSION_push(exts, req_ex);
		X509_add_ext(cert, req_ex, -1);
	}

	sk_X509_EXTENSION_free(req_exts);


	/* Sign the certificate with PC0 */
	const EVP_MD *digest;
	if(EVP_PKEY_type(my_pkey->type) == EVP_PKEY_RSA) {

		digest = EVP_sha1();

	} else if(EVP_PKEY_type(my_pkey->type) == EVP_PKEY_EC) {

		digest = EVP_ecdsa();

	}else {

		printf("Error signing the certificate, aborting operation!\n");
		return 1;
	}

	if(!(X509_sign(cert, my_pkey, digest)))
		fprintf(stderr,"Error signing cert");


	/* Write the cert to disk */
	if(!(fp = fopen(ISSUED_CERT, "w")))
		fprintf(stderr,"Error writing to file %s\n", ISSUED_CERT);
	if(PEM_write_X509(fp, cert) != 1)
		fprintf(stderr,"Error writing cert to file\n");
	fclose(fp);


	*pc1p = cert;
	*pkey = req_pkey;

//	X509_REQ_free(req);
	EVP_PKEY_free(my_pkey);

	return(0);

}

/* Add extensions to REQ */
int openssl_cert_add_ext_req(STACK_OF(X509_REQUEST) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);

	return 1;

}



/* OpenSSL special functions */

/* openssl_tool_callback function used by OpenSSL */
static void openssl_tool_callback(int p, int n, void *arg) {
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}

/* Seeding the PRNG */
int openssl_tool_seed_prng(int bytes) {
	if(!RAND_load_file("/dev/urandom", bytes))
		return 0;
	return 1;
}

/* Create AES Keys and contexts */

/* Generate Context for Encryption with Master Key */
void openssl_key_master_ctx(EVP_CIPHER_CTX *master) {

	unsigned char *aes_master_key = NULL;
	unsigned char *aes_master_iv = NULL;

	openssl_key_master_select(&aes_master_key, AES_KEY_SIZE);
	openssl_key_iv_select(&aes_master_iv, AES_IV_SIZE);

	EVP_EncryptInit(master, EVP_aes_128_cbc(), aes_master_key, aes_master_iv);

	free(aes_master_iv);
	free(aes_master_key);
}

/* Random key for input to the AES key generation, i.e. insted of user password */
void openssl_key_master_select(unsigned char **k, int b) {
	int i;
	unsigned char *key;

	if(*k == NULL || k == NULL) {
		key = malloc(b);

	} else {
		key = *k;
	}


	if(!RAND_bytes(key, b)) {
		printf("Master Key Generation Failed!\n");
		exit(0);
	}
	printf("Generated Master Key: ");

	for(i=0;i<b-1;i++) {
		printf("%02X:", key[i]);
	}
	printf("%02X\n", key[b-1]);

	*k = key;

}

void openssl_key_iv_select(unsigned char **i, int b) {

	unsigned char *iv;

	if(*i == NULL || i == NULL) {
		iv = malloc(AES_IV_SIZE);
	} else {
		iv = *i;
	}

	if(!RAND_pseudo_bytes(iv,b)){
		printf("IV Generation Failed\n");
		exit(0);
	}

	*i = iv;
}

/* Copy key (EVP_PKEY) object */
EVP_PKEY *openssl_key_copy(EVP_PKEY *key) {
	EVP_PKEY *pnew;
	int key_type;

	pnew = EVP_PKEY_new();
	switch(key->type) {

		case EVP_PKEY_RSA:
		{
			RSA *rsa = EVP_PKEY_get1_RSA(key);
			EVP_PKEY_set1_RSA(pnew,rsa);
			break;
		}

		case EVP_PKEY_EC:
		{
			EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(key);
			EVP_PKEY_set1_EC_KEY(pnew,ec_key);
			break;
		}

		case EVP_PKEY_DSA:
		{
			DSA *dsa = EVP_PKEY_get1_DSA(key);
			EVP_PKEY_set1_DSA(pnew,dsa);
			break;
		}

		case EVP_PKEY_DH:
		{
			DH *dh = EVP_PKEY_get1_DH(key);
			EVP_PKEY_set1_DH(pnew,dh);
			break;
		}

		default:
			printf("Unknown key type %d\n", key->type);
	}

	return pnew;
}


/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *openssl_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
//  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *openssl_aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

/* Generate new key (incl. IV), from master key */
unsigned char *openssl_key_generate(EVP_CIPHER_CTX *aes_master, int key_count) {

	unsigned char *ret;
	int i, tmp, ol;

	ol = 0;
	ret = malloc(EVP_CIPHER_CTX_block_size(aes_master));

	/* Create plaintext from key_count - each new key will be cipher of i=1,2,3... */
	unsigned char *plaintext = malloc(sizeof(key_count));
	memset(plaintext, 0, sizeof(plaintext));
	*plaintext = (unsigned char)key_count;
	int len = strlen((char *)plaintext)+1;

	EVP_EncryptUpdate(aes_master, &ret[0], &tmp, plaintext, len);
	ol += tmp;
	EVP_EncryptFinal(aes_master, &ret[ol], &tmp);

	printf("Generated New Current Key #%d: ",key_count);

	for(i=0;i<tmp-1;i++) {
		printf("%02X:",ret[i]);
	}
	printf("%02X\n", ret[tmp-1]);

	free(plaintext);
	return ret;

}


/* Manage sliding window to prevent replay attacks */
int tool_sliding_window(uint16_t seq_num, uint16_t id) {

	int i;
	for (i=0; i<100; i++) {

		/* Find the node id in neighbor list */
		if(id == neigh_list[i]->id) {

			/* Received Auth Sequence Number is newer/higher than last */
			if (seq_num > neigh_list[i]->last_seq_num) {

				/* Shift window according to the difference between new and last seq num */
				int difference = seq_num - neigh_list[i]->last_seq_num;
				neigh_list[i]->window = neigh_list[i]->window << difference;

				/* Set bit in window to indicate this seq num received */
				neigh_list[i]->window = neigh_list[i]->window | 1;

				/* Update new last seq num to new one */
				neigh_list[i]->last_seq_num = seq_num;

				return 1;

			}

			/* Received Auth Sequence Number is inside the window size */
			else if (seq_num >= neigh_list[i]->last_seq_num - 63) {		//window size 64

				int offset = ( neigh_list[i]->last_seq_num - seq_num ) % 64;

				/* Check whether the packet is received before, i.e. the bit is set */
				if(neigh_list[i]->window & ( 1 << offset )) {

					printf("Received replay packet, throwing away!\n\n");
					return 0;
				}

				/* If not, then add to window */
				else {

					/* Set bit in window to indicate this seq num received */
					neigh_list[i]->window = neigh_list[i]->window | ( 1 << offset );

					return 1;
				}

			}

			/* Received Auth Sequence Number is outside window size, old */
			else {

				printf("Received old (possible replay) packet, throwing away!\n");
				return 0;
			}
		}
	}
}
