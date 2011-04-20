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

#ifndef AM_H
#define AM_H

#include "batman.h"
//#include "os.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/string.h>
#include <stdio.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/asn1_mac.h>

#define MAXBUFLEN 1500	//max bytes, may have to be changed depending on certs sizes...
#define IF_NAMESIZE	16

enum role_type{
	UNAUTHENTICATED,
	AUTHENTICATED,
	MASTER
};

enum am_type{
	NEW_SIGNATURE = 0,
	CHALLENGE = 1,
	CHALLENGE_RESPONSE = 2,
	RESPONSE = 3,
	AUTHENTICATED_LIST = 4,		//Full AL update
	AL_UPDATE = 5,				//Single row update of the AL
	INVITE = 6,
	PC_REQ = 7,
	PC_ISSUE = 8
};

enum pthread_status{
	IN_USE = 0,
	READY = 99
};

enum key_algorithm{
	ECC_key = 1,
	RSA_key = 2
};

struct am_packet {
	uint16_t id;
	uint8_t type;
} __attribute__((packed));

struct challenge_packet {
	uint8_t challenge_value;
} __attribute__((packed));

struct challenge_response_packet {
	uint8_t challenge_value;
	uint8_t response_value;
} __attribute__((packed));

struct response_packet {
	uint8_t response_value;
	uint16_t auth_token;
} __attribute__((packed));

struct invite_pc_packet {
	uint8_t key_algorithm;
	uint16_t key_size;
} __attribute__((packed));

struct pc_req_packet {
	uint16_t length;
	X509_REQ req;
} __attribute__((packed));

unsigned char recvBuf[MAXBUFLEN];
unsigned char sendBuf[MAXBUFLEN];
struct addrinfo hints, *res;
int32_t am_send_socket;
int32_t am_recv_socket;
struct am_packet *rcvd_am_header;
struct challenge_packet *rcvd_challenge_packet;
struct challenge_response_packet *rcvd_challenge_response_packet;
struct response_packet *rcvd_response_packet;
char *if_device;
char *addr_prev_sender;
char *my_addr;

extern uint16_t my_auth_token;		// My Authentication Token Value, set to 0 if not authenticated
extern enum pthread_status am_status;
extern enum role_type my_role;

void authenticate_thread_init(char *, uint16_t, char *, char *);
void *authenticate();

void setup_am_socks();
void setup_am_recv_sock();
void setup_am_send_sock();
void destroy_am_socks();

enum am_type receive_am_header();

void receive_challenge();
void receive_challenge_response();
void receive_response();

void send_challenge();
void send_challenge_response();
void send_response();

void send_pc_invite();
void send_pc_req();
void send_pc_issue();

void receive_pc_invite();
void receive_pc_req();
void receive_pc_issue();




BIO *bio_err;
X509_REQ *req;
EVP_PKEY *pkey;

#define CRYPTO_DIR	"./tmp_crypto/"
#define MY_KEY		CRYPTO_DIR "my_private_key"
#define MY_CERT		CRYPTO_DIR "my_pc"
#define MY_REQ 		CRYPTO_DIR "my_pc_req"
#define RECV_REQ	CRYPTO_DIR "recv_pc_req_"
#define RECV_CERT	CRYPTO_DIR "recv_pc_"
#define ISSUED_CERT	CRYPTO_DIR "issued_pc"

void init_am();

int create_proxy_cert_req();
int create_proxy_cert_0();
int create_proxy_cert_1();

int selfsign(X509 **x509p, EVP_PKEY **pkeyp, int bits);
int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, int bits);
int mkcert(X509_REQ **reqp, X509 **pc1p, X509 **pc0p);

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);

/*
typedef struct {
	ASN1_OBJECT *policyLanguage;
	ASN1_OCTET_STRING *policy;
} ProxyPolicy;

typedef struct {
	ASN1_INTEGER *pCPathLenConstraint;
	ProxyPolicy *proxyPolicy;
} ProxyCertInfoExtension;
*/
typedef struct PROXYPOLICY_st
{
	ASN1_OBJECT *policy_language;
	ASN1_OCTET_STRING *policy;
} PROXYPOLICY;
//typedef struct PROXYPOLICY_st PROXYPOLICY;

typedef struct PROXYCERTINFO_st
{
	ASN1_INTEGER *path_length;       /* [ OPTIONAL ] */
	PROXYPOLICY *policy;
} PROXYCERTINFO;
//typedef struct PROXYCERTINFO_st PROXYCERTINFO;


/*
#define ASN1_F_PROXYPOLICY_NEW          450
#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14" //tester
#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
#define LIMITED_PROXY_SN                "LIMITED_PROXY"
#define LIMITED_PROXY_LN                "GSI limited proxy"
*/

//temp, for creating certs
//int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
//int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);



//Temp variables for simple auth
extern uint8_t is_authenticated;	// O eller 1
extern uint8_t my_challenge;		// My Challenge Value, set to 0 if no challenge to send
extern uint8_t my_response;			// My Response Value, set to 0 if no response to send

extern uint8_t tmp_response;		// Temporary response value, used in calculation
extern uint8_t generated_challenge;	// My last generated Challenge Value, used to verify received response in Request Message
extern uint8_t generated_request;	// My last generated Request (challenge in a Request message), used to verify received Response
extern uint8_t generated_auth;		// My generated Authentication Value to be used if authentication completes
extern uint8_t rcvd_challenge;		// Received Challenge Value, 0 if no challenge
extern uint8_t rcvd_response;		// Received Response Value, 0 if no response
extern uint16_t rcvd_auth_token;		// Received Authentication Token, 0 if not authenticated, or if not end of handshake
extern uint8_t expecting_token;		// Expected Value of received authentication token
extern uint32_t	random_wait_time;	// Random backoff time, tmp_wait + curr_time
extern uint32_t tmp_wait;			// Random backoff time value



#endif
