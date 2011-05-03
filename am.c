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



/* External Variables */
role_type my_role;
pthread_t am_main_thread;
uint32_t new_neighbor, prev_neighbor;
uint32_t trusted_neighbors[100];
uint8_t num_trusted_neighbors;
char signature_extract[3];


/* Variables used by am thread */
pthread_t am_thread;
sockaddr_in my_addr, broadcast_addr;
char *interface;
uint16_t id;
int32_t am_send_socket, am_recv_socket, packet_len;


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

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* AM main thread */
void *am_main() {

	sockaddr_in *dest;
	sockaddr_storage recv_addr;
	socklen_t addr_len;
	fd_set readfds;
	timeval tv;
	char am_recv_buf[MAXBUFLEN];
	char *am_recv_buf_ptr;
	char am_send_buf[MAXBUFLEN];
	char *am_send_buf_ptr;
	char *am_payload_ptr;
	EVP_PKEY *pkey = NULL;
	unsigned char *subject_name = NULL;
	ssize_t data_rcvd;
	am_type am_type_rcvd;

	/* Load all algorithms and error messages used by OpenSSL */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Setup socks for the all AM purposes, except initial authentication */
	setup_am_socks(&am_recv_socket, &am_send_socket);

	/* Clear the set */
	FD_ZERO(&readfds);

	/* Add descriptor (receiver socket) to set */
	FD_SET(am_recv_socket, &readfds);

	/* Set time interval for checking the socket */
	tv.tv_sec = 0;
	tv.tv_usec = 100000;

	/* Set user ID */
	char addr_char[16];
	addr_to_string(my_addr.sin_addr.s_addr, addr_char, sizeof (addr_char));
	id = inet_addr(addr_char) % UINT16_MAX;


	/* If you are the SP, create a PC0 */
	if(my_role == SP) {
		create_proxy_cert_0(pkey, subject_name);

		/* Send Signature */
		create_signature();
		send_signature();

	}

	/* Else create a PC Request	 */
	else {
		create_proxy_cert_req(pkey, subject_name);
	}


	data_rcvd = 0;
	am_type_rcvd = NO_AM_DATA;
	addr_len = sizeof recv_addr;
	prev_neighbor = 0;
	am_recv_buf_ptr = am_recv_buf;
	am_send_buf_ptr = am_send_buf;
	am_payload_ptr = NULL;
	dest = NULL;

	/* Main loop for the AM thread, will only exit when Batman is terminated */
	while(1) {

		/* Check For Incoming Data On AM Socket */
		FD_ZERO(&readfds);
		FD_SET(am_recv_socket, &readfds);
		select(am_recv_socket+1, &readfds, NULL, NULL, &tv);
		if(FD_ISSET(am_recv_socket,&readfds)) {
			memset(&am_recv_buf, 0, MAXBUFLEN);
			data_rcvd = recvfrom(am_recv_socket, &am_recv_buf, MAXBUFLEN - 1, 0, (struct sockaddr *)&recv_addr, &addr_len); //maybe check length is greater than am_header?
		}
		if(data_rcvd) {
			am_type_rcvd = extract_am_header(am_recv_buf_ptr, &am_payload_ptr);

			switch (am_type_rcvd) {
				case NO_AM_DATA:
					break;

				case NEW_SIGNATURE:

					break;

				case AUTHENTICATED_LIST:

					break;

				case AL_UPDATE:

					break;

				case INVITE:
					printf("Received Invite!\n");
					dest = (sockaddr_in *) malloc(sizeof(sockaddr_in));
					dest->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
					dest->sin_family = AF_INET;
					dest->sin_port = htons(AM_PORT);
					send_pc_req(dest);
					free(dest);

					break;

				case PC_REQ:
					printf("Received PC Request!\n");

					if((uint32_t)((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr.s_addr == prev_neighbor) {

						char *recv_addr_string = malloc(16);
						recv_addr_string = inet_ntoa(((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr);
						if(receive_pc_req(recv_addr_string, am_payload_ptr)) {
							dest = (sockaddr_in *) malloc(sizeof(sockaddr_in));
							dest->sin_addr = ((sockaddr_in*)((sockaddr *)&recv_addr))->sin_addr;
							dest->sin_family = AF_INET;
							dest->sin_port = htons(AM_PORT);
							create_proxy_cert_1(recv_addr_string);
							send_pc_issue(dest);
							free(dest);

						}

					} else
						printf("Request from unknown node!\n");

					break;

				case PC_ISSUE:
					printf("Received PC Issue!\n");
					if(receive_pc_issue(am_payload_ptr)) {
						printf("\n\nI w0Z heR3!!\n\n\n");
					}

					break;

				default:
					printf("Received unknown AM Type %d, exiting with condition 1\n",am_type_rcvd);
					exit(1);
			}
			am_type_rcvd = NO_AM_DATA;
			data_rcvd = 0;
		}

		/* The rest is for SP only! */
		if(my_role == SP) {

			/* Check for new neighbors */
			if(new_neighbor && !prev_neighbor) {
				prev_neighbor = new_neighbor;
				dest = (sockaddr_in *) malloc(sizeof(sockaddr_in));
				dest->sin_addr.s_addr = new_neighbor;
				dest->sin_family = AF_INET;
				dest->sin_port = htons(AM_PORT);
				send_pc_invite(dest);
				free(dest);

			}


		}

	}




}

/* Create PC0 for the SP */
int create_proxy_cert_0(EVP_PKEY *pkey, unsigned char *subject_name) {

	X509 *pc0 = NULL;
	FILE *fp;
	BIO *bio_err;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

	selfsign(&pc0, &pkey, subject_name);

	RSA_print_fp(stdout,pkey->pkey.rsa,0);
	X509_print_fp(stdout,pc0);

	PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
	PEM_write_X509(stdout,pc0);

	/* Write X509 PC0 to a file */
	if(!(fp = fopen(MY_CERT, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_CERT);
	if(PEM_write_X509(fp, pc0) != 1)
		fprintf(stderr, "Error while writing request to file %s", MY_CERT);
	fclose(fp);

	/* Write Private Key to a file */
	if(!(fp = fopen(MY_KEY, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_KEY);
	if(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1)
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
int create_proxy_cert_req(EVP_PKEY *pkey, unsigned char *subject_name) {

	X509_REQ *req;
	FILE *fp;
	BIO *bio_err;

	req = NULL;
	pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	mkreq(&req, &pkey, subject_name);

	RSA_print_fp(stdout, pkey->pkey.rsa, 0);	//pkey.rsa changed with pkey.ec
	X509_REQ_print_fp(stdout, req);
	PEM_write_X509_REQ(stdout, req);

	/* Write Private Key to a file */
	if(!(fp = fopen(MY_KEY, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_KEY);
	if(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1)
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
int create_proxy_cert_1(char *addr) {

	char *filename;
	FILE *fp;
	X509 *pc0 = NULL, *pc1 = NULL;
	X509_REQ *req = NULL;

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


	if(mkcert(&req, &pc1, &pc0) == 0) {
		X509_print_fp(stdout,pc1);
		PEM_write_X509(stdout,pc1);

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

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);

}


/* Create Signature */

void create_signature() {

	FILE *fp;
	unsigned char *pseudo_random = NULL;
	unsigned char *sig_buf = NULL;
	unsigned int sig_len;
	BIO *bio, *b64;
	EVP_MD_CTX *md_ctx;

	/* Read my private key */
	if(!(fp = fopen(MY_KEY, "r")))
		fprintf(stderr, "Error opening file %s for reading!\n",MY_KEY);
	if(!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		fprintf(stderr,"Error reading private key of SP");
	fclose(fp);

	/* Create Random Bytes String */
	pseudo_random = malloc(20);
	if(!RAND_pseudo_bytes(pseudo_random, 20)) {
		fprintf(stderr, "Could not generate pseudo random value for signature\n");
	}

	/* Create Message Digest of Random String to Sign (Signature) */
	md_ctx = EVP_MD_CTX_create();
	EVP_SignInit(md_ctx, EVP_sha1());
	EVP_SignUpdate(md_ctx, pseudo_random, sizeof(pseudo_random));
	sig_len = EVP_PKEY_size(pkey);
	sig_buf = malloc(sig_len);
	if(EVP_SignFinal(md_ctx, sig_buf, &sig_len, pkey) != 1) {
		ERR_print_errors_fp(stderr);
	}
	printf("Created new signature!\n");

	if(!(fp = fopen(MY_SIG, "w")))
		fprintf(stderr, "Error opening file %s for writing!\n",MY_SIG);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_write(bio, sig_buf, sig_len);

	BIO_flush(bio);
	fclose(fp);
	BIO_free_all(bio);

	EVP_MD_CTX_cleanup(md_ctx);

	/* Save signature extract */
	memcpy(&signature_extract, sig_buf, sizeof(signature_extract));

}

/* Send Signature */
void send_signature() {

	am_packet *am_header;
	char *ptr;
	int32_t packet_len;
	FILE *fp;
	char *buf;

	am_header = (am_packet *) malloc(sizeof(am_packet));
	am_header->id = id;
	am_header->type = NEW_SIGNATURE;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, am_header, sizeof(am_packet));
	ptr = buf;
	ptr += sizeof(am_packet);
	packet_len = sizeof(am_packet);
	if(!(fp = fopen(MY_SIG, "r")))
			fprintf(stderr, "Error opening file %s for reading!\n",MY_SIG);
	packet_len += fread(ptr, 1, PEM_BUFSIZE, fp);
	fclose(fp);

	send_udp_packet((unsigned char *)buf, packet_len, &broadcast_addr, am_send_socket, NULL);
	printf("Sending new signature!\n");

}

/* Send PC Handshake Invite */
void send_pc_invite(sockaddr_in *sin_dest) {

	char *buf;
	char *ptr;
	am_packet *header;
	invite_pc_packet *payload;

	header = (am_packet *) malloc(sizeof(am_packet));
	header->id = id;
	header->type = INVITE;

	payload = (invite_pc_packet *) malloc(sizeof(invite_pc_packet));
	payload->key_algorithm = RSA_key;
	payload->key_size = 2048;

	buf = malloc(MAXBUFLEN);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, header, sizeof(am_packet));
	ptr = buf;
	ptr += sizeof(am_packet);
	memcpy(ptr, payload, sizeof(invite_pc_packet));

	packet_len = sizeof(am_packet);
	packet_len += sizeof(invite_pc_packet);

	send_udp_packet((unsigned char *)buf, packet_len, sin_dest, am_send_socket, NULL);

	free(buf);
	free(header);

}

/* Send PC Request */
void send_pc_req(sockaddr_in *sin_dest) {

	am_packet *header;
	char *buf;
	FILE *fp;
	char *ptr;

	header = (am_packet *) malloc(sizeof(am_packet));
	header->id = id;
	header->type = PC_REQ;

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

	send_udp_packet((unsigned char *)buf, packet_len, sin_dest, am_send_socket, NULL);

	free(header);
	free(buf);

}

/* Send the issued PC1 */
void send_pc_issue(sockaddr_in *sin_dest) {

	char *buf;
	am_packet *am_header;
	char *ptr;
	int32_t packet_len;
	FILE *fp;

	am_header = (am_packet *) malloc(sizeof(am_packet));
	am_header->id = id;
	am_header->type = PC_ISSUE;

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

	send_udp_packet((unsigned char *)buf, packet_len, sin_dest, am_send_socket, NULL);

	free(am_header);
	free(buf);
}





/* Extract AM Data Type From Received AM Packet */
am_type extract_am_header(char *buf, char **ptr) {

	am_packet *header;
	header = (am_packet *)buf;

	*ptr = buf;
	*ptr += sizeof(am_packet);

	return header->type;

}

/* Receive Invite */
//void receive_pc_invite() {
//
//	recv_invite = tmpPtr;
//	recv_invite = (invite_pc_packet *)recv_invite;
//	requested_key_algorithm = recv_invite->key_algorithm;
//	requested_key_size = recv_invite->key_size;
//}

/* Receive PC Request */
int receive_pc_req(char *addr, char *ptr) {

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
int receive_pc_issue(char *ptr) {

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

void setup_am_socks(int32_t *recvsock, int32_t *sendsock) {

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

	/* Setup Receive and Send Sockets */
	if(!setup_am_recv_socks(recvsock, res))
		destroy_am_socks(sendsock, recvsock, res);
	if(!setup_am_send_socks(sendsock))
		destroy_am_socks(sendsock, recvsock, res);
}

int setup_am_recv_socks(int32_t *recvsock, addrinfo *res) {

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

int setup_am_send_socks(int32_t *sendsock) {

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

void destroy_am_socks(int32_t *send, int32_t *recv, addrinfo *res) {

	printf("WARNING: Destroying AM Sockets!\n");
	if (*recv != 0)
		close(*recv);
	if (*send != 0)
		close(*send);
	*recv = 0;
	*send = 0;

	freeaddrinfo(res);
}







/* Certificate and Requests Creation Helper Functions */

/* PC0 Creation and Selfsigning */
int selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name) {
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	int bits = 512;


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



	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		{
		abort();
		goto err;
		}
	rsa=NULL;

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
	subject_name = (unsigned char *)malloc(SUBJECT_NAME_SIZE);
	sprintf((char *)subject_name,"SP_%d",rand()%UINT32_MAX);
	X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, subject_name, -1, -1, 0);

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

	if (!X509_sign(x,pk,EVP_md5()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
}


/* PC REQ Creation */
int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name) {
	X509_REQ *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	int bits = 512;

	if ((pk=EVP_PKEY_new()) == NULL)
		goto err;

	if ((x=X509_REQ_new()) == NULL)
		goto err;

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		goto err;

	rsa=NULL;

	X509_REQ_set_pubkey(x,pk);

	name=X509_REQ_get_subject_name(x);

	/*
	 * This is where we add the Subject (unique) Common Name.
	 * The Issuer name will be prepended by the issuer on creation.
	 * TODO: Maybe use hash of public key, for now only a random number
	 */
	subject_name = (unsigned char *)malloc(SUBJECT_NAME_SIZE);
	sprintf((char *)subject_name,"%d",rand()%UINT32_MAX);
	X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, subject_name, -1, -1, 0);

#ifdef REQUEST_EXTENSIONS
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

	add_ext_req(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");


	/* PROCYCERTINFO */

	//Les http://root.cern.ch/svn/root/vendors/xrootd/current/src/XrdCrypto/XrdCryptosslgsiAux.cc

	//Create ProxyPolicy
    PROXYPOLICY *proxyPolicy;
    proxyPolicy = NULL;
//    ASN1_CTX c; /* Function below needs this to be defined */
//    M_ASN1_New_Malloc(proxyPolicy, PROXYPOLICY);
    proxyPolicy = (PROXYPOLICY *)OPENSSL_malloc(sizeof(PROXYPOLICY));
    proxyPolicy->policy_language = OBJ_nid2obj(NID_id_ppl_inheritAll);
    proxyPolicy->policy = NULL;
//    M_ASN1_New_Error(ASN1_F_PROXYPOLICY_NEW);

    //Create ProxyCertInfo
    PROXYCERTINFO *proxyCertInfo;
    proxyCertInfo = NULL;
//    M_ASN1_New_Malloc(proxyCertInfo, PROXYCERTINFO);
    proxyCertInfo = (PROXYCERTINFO *)OPENSSL_malloc(sizeof(PROXYCERTINFO));
    memset(proxyCertInfo, (int) NULL, sizeof(PROXYCERTINFO));
    proxyCertInfo->path_length = NULL;
    proxyCertInfo->policy = proxyPolicy;


    //Mucho try-as-i-go, need cleanup!!!
    X509V3_CTX ctx;
    X509V3_CONF_METHOD method = { NULL, NULL, NULL, NULL };
    long db = 0;

    char language[80];
    int pathlen;
    unsigned char *policy = NULL;
    int policy_len;
    char *value;
    char *tmp;

    ASN1_OCTET_STRING *             ext_data;
    int                             length;
    unsigned char *                 data;
    unsigned char *                 der_data;
    X509_EXTENSION *                proxyCertInfo_ext;
    const X509V3_EXT_METHOD *       proxyCertInfo_ext_method;

    proxyCertInfo_ext_method = X509V3_EXT_get_nid(NID_proxyCertInfo);

//    proxyCertInfo_ext_method = X509V3_EXT_get_nid(OBJ_txt2nid(PROXYCERTINFO_OLD_OID));



//    OBJ_obj2txt(language, 80, proxyCertInfo->policy->policy_language, 1);
//    sprintf(&language, "blablabla");
//    proxyCertInfo->policy->policy_language = OBJ_txt2obj(language, 1);

    pathlen = 0;
    ASN1_INTEGER_set(&(proxyCertInfo->path_length), (long)pathlen);

//    if (proxyCertInfo->policy->policy) {
//    	policy_len = M_ASN1_STRING_length(proxyCertInfo->policy->policy);
//    	policy = malloc(policy_len + 1);
//    	memcpy(policy, M_ASN1_STRING_data(proxyCertInfo->policy->policy), policy_len);
//    	policy[policy_len] = '\0';
//    }


//    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0L);
//    ctx.db_meth = &method;
//    ctx.db = &db;

//    pci_ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_proxyCertInfo, value);
//    X509_EXTENSION_set_critical(pci_ext, 1);

//    add_ext(exts, NID_proxyCertInfo, value);

    if(proxyCertInfo_ext_method) {
    	printf("\n\next_method\n\n\n");
    }
    if (proxyCertInfo_ext_method->i2v) {
    	printf("\n\next_method->i2v\n\n\n");
    }
    if(proxyCertInfo_ext_method->v2i) {
    	printf("\n\next_method->v2i\n\n\n");
    }
    if (proxyCertInfo_ext_method->i2r) {
    	printf("\n\next_method->i2r\n\n\n");
    }
    if(proxyCertInfo_ext_method->r2i) {
    	printf("\n\next_method->r2i\n\n\n");
    }


    printf("\n\nTEST\n\n\n");
    proxyCertInfo_ext_method->i2d(proxyCertInfo, NULL);


//    } else {
//    	printf("\n\nFAEN\n\n\n");
//    }




#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		add_ext(x, nid, "example comment alias");
	}
#endif

	/* Now we've created the extensions we add them to the request */

	X509_REQ_add_extensions(x, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

#endif

	if (!X509_REQ_sign(x,pk,EVP_sha1()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);

}


/* PC1 Creation */
int mkcert(X509_REQ **reqp,X509 **pc1p, X509 **pc0p) {
	EVP_PKEY *req_pkey, *my_pkey;
	X509_NAME *name, *req_name, *issuer_name;
	X509_NAME_ENTRY *req_name_entry;
	X509  *cert;
	FILE *fp;

	/* Verify signature on REQ */
	if(!(req_pkey = X509_REQ_get_pubkey(*reqp)))
		fprintf(stderr,"Error getting public key from request");
	if(X509_REQ_verify(*reqp, req_pkey) != 1)
		fprintf(stderr,"Error verifying signature on certificate");

	/* Read my private key */
	if(!(fp = fopen(MY_KEY, "r")))
		fprintf(stderr, "Error opening file %s for reading!\n",RECV_REQ);
	if(!(my_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		fprintf(stderr,"Error reading private key of SP");
	fclose(fp);


	/* Read Subject Name of request */
	if(!(req_name = X509_REQ_get_subject_name(*reqp)))
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


	/* Set public key */
	if(X509_set_pubkey(cert, req_pkey) != 1)
		fprintf(stderr,"Error setting the public key to the certificate\n");

	/* Set lifetime of cert */
	if(!(X509_gmtime_adj(X509_get_notBefore(cert), 0)))
		fprintf(stderr,"Error setting the start lifetime of cert");
	if(!(X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*8)))
		fprintf(stderr,"Error setting the end lifetime of cert");

	/* Sign the certificate with PC0 */
	if(EVP_PKEY_type(my_pkey->type) == EVP_PKEY_RSA) {
		const EVP_MD *digest = EVP_sha1();

		if(!(X509_sign(cert, my_pkey, digest)))
			fprintf(stderr,"Error signing cert");
	} else {
		printf("Error signing the certificate, aborting operation!\n");
		return 1;
	}




	/* Write the cert to disk */
	if(!(fp = fopen(ISSUED_CERT, "w")))
		fprintf(stderr,"Error writing to file %s\n", ISSUED_CERT);
	if(PEM_write_X509(fp, cert) != 1)
		fprintf(stderr,"Error writing cert to file\n");
	fclose(fp);


	*pc1p = cert;

	EVP_PKEY_free(my_pkey);

	return(0);

}

/* Add extensions to REQ */
int add_ext_req(STACK_OF(X509_REQUEST) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);

	return 1;

}

/* Callback function used by OpenSSL */
static void callback(int p, int n, void *arg) {
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}



/* OpenSSL special functions */

/* Seeding the PRNG */
int seed_prng(int bytes) {
	if(!RAND_load_file("/dev/urandom", bytes))
		return 0;
	return 1;
}
