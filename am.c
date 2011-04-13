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

struct addrinfo hints, *res;
int32_t am_send_socket = 0;
int32_t am_recv_socket = 0;
pthread_t am_thread;
enum pthread_status am_status = READY;
//struct bat_packet *bat_packet;
//struct batman_if *batman_if;
int auth_thread_int = 99;
int32_t packet_len = 0;
struct am_packet *am_header;
struct challenge_packet *challenge_packet;
struct challenge_response_packet *challenge_response_packet;
struct response_packet *response_packet;
struct sockaddr_in sin_dest;
char *if_device;
void *tmpPtr;
enum am_type rcvd_type;
uint16_t my_auth_token = 0;
enum role_type my_role = UNAUTHENTICATED;


//Temp variables
uint8_t bool_extended = 0;
uint8_t is_authenticated = 0;
//my_auth_token = 0;
uint8_t my_challenge = 0;
uint8_t my_response = 0;
uint8_t rcvd_challenge = 0;
uint8_t rcvd_response = 0;
uint16_t rcvd_auth_token = 0;
uint8_t expecting_token = 0;
uint8_t num_waits = 0;
uint32_t random_wait_time = 0;
uint8_t generated_challenge = 0;
uint8_t generated_request = 0;
uint8_t generated_auth = 0;
uint8_t tmp_response = 0;
uint32_t tmp_wait = 0;

//void dump_memory(void* data, size_t len)
//{
//size_t i;
//printf("Data in [%p..%p): ",data,data+len);
//for (i=0;i<len;i++)
//printf("%02X ", ((unsigned char*)data)[i] );
//printf("\n");
//}
//
//	dump_memory(&recvBuf, 4);
//	dump_memory(tmpPtr, 4);


void authenticate_thread_init(char *d, uint16_t auth_token, char *prev_sender, char *my_addr_string) {
	if (am_status != IN_USE ) {
		am_status = IN_USE;
		printf("ENTER AM MODULE\n");

		if_device = (char *) malloc(strlen(d)+1);
		memset(if_device, 0, strlen(d)+1);
		memcpy(if_device, d, strlen(d));
//		if_device[strlen(if_device)] = '\0'; 	//might have to be used like this, check if errors appear later...

		rcvd_auth_token = auth_token;

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

	//Both Unauthenticated
	if((my_auth_token == 0) && (rcvd_auth_token == 0)) {

		setup_am_socks();

		if(inet_addr(addr_prev_sender)<inet_addr(my_addr)) {// && my_challenge==0) {
			printf("RECEIVED UNAUTHENTICATED OGM\n");
			send_challenge();
			printf("my_challenge = %d\n\n",my_challenge);
		}

		while(1) {
			rcvd_type = receive_am_header();

			if(rcvd_type == NEW_SIGNATURE) {
				printf("RECEIVED A NEW SIGNATURE\n\n");

			} else if(rcvd_type == CHALLENGE) {
				printf("RECEIVED CHALLENGE\n");
				receive_challenge();
				printf("rcvd_challenge = %d\n",rcvd_challenge);
				send_challenge_response();
				printf("my_response = %d\n",my_response);
				printf("my_challenge = %d\n\n",my_challenge);

			} else if(rcvd_type == CHALLENGE_RESPONSE) {
				printf("RECEIVED CHALLENGE_RESPONSE\n");
				receive_challenge_response();
				printf("rcvd_response = %d\n",rcvd_response);
				printf("rcvd_challenge = %d\n",rcvd_challenge);
				printf("my_response = %d\n\n",my_response);
				my_role = MASTER;
				break;

			} else if(rcvd_type == RESPONSE) {
				printf("RECEIVED RESPONSE\n");
				receive_response();
				printf("rcvd_response = %d\n",rcvd_response);
				my_role = AUTHENTICATED;
				break;

			} else {
				printf("RECEIVED UNRECOGNIZABLE AM HEADER\n");
			}
		}	//end while

	}

	//I am authenticated, other node is unauth
	else if(rcvd_auth_token == 0) {
		setup_am_socks();

		printf("RECEIVED UNAUTHENTICATED OGM\n");
		send_challenge();
		printf("my_challenge = %d\n\n",my_challenge);

		while(1) {
			rcvd_type = receive_am_header();

			if(rcvd_type == CHALLENGE_RESPONSE) {
				printf("RECEIVED CHALLENGE_RESPONSE\n");
				receive_challenge_response();
				printf("rcvd_response = %d\n",rcvd_response);
				printf("rcvd_challenge = %d\n",rcvd_challenge);
				printf("my_response = %d\n\n",my_response);
				break;

			} else {
				printf("RECEIVED UNRECOGNIZABLE AM HEADER\n");
			}
		}	//end while

	}

	//I'm unauth, other node is auth
	else if(my_auth_token == 0) {

		setup_am_socks();

		while(1) {
			rcvd_type = receive_am_header();

			if(rcvd_type == CHALLENGE) {
				printf("RECEIVED CHALLENGE\n");
				receive_challenge();
				printf("rcvd_challenge = %d\n",rcvd_challenge);
				send_challenge_response();
				printf("my_response = %d\n",my_response);
				printf("my_challenge = %d\n\n",my_challenge);

			} else if(rcvd_type == RESPONSE) {
				printf("RECEIVED RESPONSE\n");
				receive_response();
				printf("rcvd_response = %d\n",rcvd_response);
				break;

			} else {
				printf("RECEIVED UNRECOGNIZABLE AM HEADER\n");
			}
		}	//end while

	}


	destroy_am_socks();
	free(if_device);
	free(addr_prev_sender);
	free(my_addr);
	sleep(5);
	printf("EXIT AM MODULE\n");
	am_status = READY;
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

	setsockopt(am_recv_socket, SOL_SOCKET, SO_BINDTODEVICE, if_device, strlen(if_device) + 1);

//	bind(am_recv_socket, (struct sockaddr*)&sin_dest, sizeof(sin_dest));	//for this to work, sender must be assigned same port number...
	bind(am_recv_socket, res->ai_addr, res->ai_addrlen);

}

void setup_am_send_sock() {

	if ( (am_send_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
		printf("Error - can't create AM send socket: %s\n", strerror(errno) );
		destroy_am_socks();
	}

	setsockopt(am_send_socket, SOL_SOCKET, SO_BINDTODEVICE, if_device, strlen(if_device) + 1);
	fcntl(am_send_socket, F_SETFL, O_NONBLOCK);

}

void destroy_am_socks() {
	if (am_recv_socket != 0)
		close(am_recv_socket);

	if (am_send_socket != 0)
		close(am_send_socket);

	am_recv_socket = 0;
	am_send_socket = 0;

	freeaddrinfo(res);
}




enum am_type receive_am_header() {
	memset(&recvBuf, 0, MAXBUFLEN);

	while((unsigned)recvfrom(am_recv_socket, &recvBuf, MAXBUFLEN - 1, 0, NULL, NULL) < sizeof(struct am_packet)) {
		printf(".\n");
	}

	rcvd_am_header = (struct am_packet *)recvBuf;
	tmpPtr = &recvBuf;
	tmpPtr += sizeof(struct am_packet);

	printf("\nTYPE = %d\n\n",rcvd_am_header->type);

	return rcvd_am_header->type;

}

void receive_challenge() {

	rcvd_challenge_packet = tmpPtr;
	rcvd_challenge_packet = (struct challenge_packet *)rcvd_challenge_packet;
	rcvd_challenge = rcvd_challenge_packet->challenge_value;
}

void receive_challenge_response() {
	rcvd_challenge_response_packet = tmpPtr;
	rcvd_challenge_response_packet = (struct rcvd_challenge_response_packet *)rcvd_challenge_response_packet;

	rcvd_challenge = rcvd_challenge_response_packet->challenge_value;
	rcvd_response = rcvd_challenge_response_packet->response_value;

	my_challenge = (2*my_challenge) % UINT8_MAX;
	my_challenge = (my_challenge == 0 ? 1 : my_challenge);

	if(my_challenge==rcvd_response) {
		printf("Correct Response\n");
		send_response();
	} else printf("Wrong Response\n");

}

void receive_response() {
	rcvd_response_packet = tmpPtr;
	rcvd_response_packet = (struct rcvd_response_packet *)rcvd_response_packet;

	rcvd_response = rcvd_response_packet->response_value;

	my_challenge = (2*my_challenge) % UINT8_MAX;
	my_challenge = (my_challenge == 0 ? 1 : my_challenge);

	if(my_challenge==rcvd_response) {
		printf("Correct Response\n");
		my_auth_token = rcvd_response_packet->auth_token;
	} else printf("Wrong Response\n");
}


void send_challenge() {

	sleep(1);	//Make sure other node is ready to receive challenge

	am_header = (struct am_packet *) malloc(sizeof(struct am_packet));
	am_header->id = inet_addr(my_addr) % UINT16_MAX;
	am_header->type = CHALLENGE;

	my_challenge = 1 + (rand() % UINT8_MAX);
	challenge_packet = (struct challenge_packet *) malloc(sizeof(struct challenge_packet));
	challenge_packet->challenge_value = my_challenge;

	memset(&sendBuf, 0, sizeof(sendBuf));
	memcpy(&sendBuf, am_header, sizeof(struct am_packet));
	tmpPtr = &sendBuf;
	tmpPtr += sizeof(struct am_packet);
	memcpy(tmpPtr, challenge_packet, sizeof(struct challenge_packet));
	packet_len = sizeof(struct am_packet);
	packet_len += sizeof(struct challenge_packet);

	send_udp_packet((unsigned char *)&sendBuf, packet_len, &sin_dest, am_send_socket, NULL);

}


void send_challenge_response(){
	am_header = (struct am_packet *) malloc(sizeof(struct am_packet));
	am_header->id = inet_addr(my_addr) % UINT16_MAX;
	am_header->type = CHALLENGE_RESPONSE;

	my_response = (2*rcvd_challenge) % UINT8_MAX;
	my_response = (my_response == 0 ? 1 : my_response);
	challenge_response_packet = (struct challenge_response_packet *) malloc(sizeof(struct challenge_response_packet));
	challenge_response_packet->response_value = my_response;

	my_challenge = 1 + (rand() % UINT8_MAX);
	challenge_response_packet->challenge_value = my_challenge;

	memset(&sendBuf, 0, sizeof(sendBuf));
	memcpy(&sendBuf, am_header, sizeof(struct am_packet));
	tmpPtr = &sendBuf;
	tmpPtr += sizeof(struct am_packet);
	memcpy(tmpPtr, challenge_response_packet, sizeof(struct challenge_response_packet));
	packet_len = sizeof(struct am_packet);
	packet_len += sizeof(struct challenge_response_packet);

	send_udp_packet((unsigned char *)&sendBuf, packet_len, &sin_dest, am_send_socket, NULL);

}


void send_response() {
	am_header = (struct am_packet *) malloc(sizeof(struct am_packet));
	am_header->id = inet_addr(my_addr) % UINT16_MAX;
	am_header->type = RESPONSE;

	my_response = (2*rcvd_challenge) % UINT8_MAX;
	my_response = (my_response == 0 ? 1 : my_response);
	if(my_auth_token == 0) {
		my_auth_token = 1 + (rand() % UINT16_MAX);
		my_auth_token = (my_auth_token == 0 ? 1 : my_auth_token);
	}

	response_packet = (struct response_packet *) malloc(sizeof(struct response_packet));
	response_packet->response_value = my_response;
	response_packet->auth_token = my_auth_token;

	memset(&sendBuf, 0, sizeof(sendBuf));
	memcpy(&sendBuf, am_header, sizeof(struct am_packet));
	tmpPtr = &sendBuf;
	tmpPtr += sizeof(struct am_packet);
	memcpy(tmpPtr, response_packet, sizeof(struct response_packet));
	packet_len = sizeof(struct am_packet);
	packet_len += sizeof(struct response_packet);

	send_udp_packet((unsigned char *)&sendBuf, packet_len, &sin_dest, am_send_socket, NULL);
}


void init_am() {
	BIO *bio_err;
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;

	create_proxy_cert_req();
	free_proxy_cert_req;
}

void create_proxy_cert_req() {

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

//	mkreq(&req, &pkey,512, 0, 1); //512 changed to EC key size
	mkreq();

	RSA_print_fp(stdout, pkey->pkey.rsa, 0);	//pkey.rsa changed with pkey.ec
	X509_REQ_print_fp(stdout, req);

	PEM_write_X509_REQ(stdout, req);


	free_proxy_cert_req();
}

void free_proxy_cert_req(){

	X509_REQ_free(req);
	EVP_PKEY_free(pkey);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

}

static void callback(int p, int n, void *arg) {
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
}

//int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days) {
int mkreq() {
	X509_REQ *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	STACK_OF(X509_EXTENSION) *exts = NULL;

	if ((pk=EVP_PKEY_new()) == NULL)
		goto err;

	if ((x=X509_REQ_new()) == NULL)
		goto err;

	rsa=RSA_generate_key(512,RSA_F4,callback,NULL);
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
	unsigned char subject_name[32];
	sprintf(&subject_name,"%d",rand()%UINT32_MAX);
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

	add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");


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

	req=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);

}

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);

	return 1;

}
