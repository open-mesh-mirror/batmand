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
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
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
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/asn1_mac.h>

#define IF_NAMESIZE	16
#define AM_PORT 64305


typedef enum role_type_en{
	UNAUTHENTICATED,
	AUTHENTICATED,
	MASTER,
	SP
} role_type;

typedef enum am_type_en{
	NO_AM_DATA = 0,
	NEW_SIGNATURE = 1,
	AUTHENTICATED_LIST = 2,		//Full AL update
	AL_UPDATE = 3,				//Single row update of the AL
	INVITE = 4,
	PC_REQ = 5,
	PC_ISSUE = 6
} am_type;

typedef enum pthread_status_en{
	IN_USE = 0,
	READY = 99
} pthread_status;

typedef enum key_algorithm_en{
	ECC_key = 1,
	RSA_key = 2
} key_algorithm;

typedef struct am_packet_st {
	uint16_t id;
	uint8_t type;
} __attribute__((packed)) am_packet;

typedef struct challenge_packet_st {
	uint8_t challenge_value;
} __attribute__((packed)) challenge_packet;

typedef struct challenge_response_packet_st {
	uint8_t challenge_value;
	uint8_t response_value;
} __attribute__((packed)) challenge_response_packet;

typedef struct response_packet_st {
	uint8_t response_value;
	uint16_t auth_token;
} __attribute__((packed)) response_packet;

typedef struct invite_pc_packet_st {
	uint8_t key_algorithm;
	uint16_t key_size;
} __attribute__((packed)) invite_pc_packet;

typedef struct pc_req_packet_st {
	uint16_t length;
	X509_REQ req;
} __attribute__((packed)) pc_req_packet;

//unsigned char recvBuf[MAXBUFLEN];	//tror ikke trengs
//unsigned char sendBuf[MAXBUFLEN];	//tor ikke trengs
struct addrinfo hints, *res;	//tror ikke trengs
int32_t auth_send_socket;	//tror ikke trengs
int32_t auth_recv_socket;	//tror ikke denne trengs
am_packet *rcvd_am_header;	//tror ikke trengs
challenge_packet *rcvd_challenge_packet;	//tror ikke trengs
challenge_response_packet *rcvd_challenge_response_packet;	//tror ikke trengs
response_packet *rcvd_response_packet;	//tror ikke trengs
char *if_device;
char *addr_prev_sender;


extern uint16_t my_auth_token;		// My Authentication Token Value, set to 0 if not authenticated
extern pthread_status am_status;


void setup_am_socks();
void setup_am_recv_sock();
void setup_am_send_sock();
void destroy_am_socks();

am_type receive_am_header();

void receive_challenge();
void receive_challenge_response();
void receive_response();

void send_challenge();
void send_challenge_response();
void send_response();



void receive_pc_invite();




BIO *bio_err;
X509_REQ *req;
EVP_PKEY *pkey;

#define CRYPTO_DIR	"./tmp_crypto/"
#define MY_KEY		CRYPTO_DIR "my_private_key"
#define MY_CERT		CRYPTO_DIR "my_pc"
#define MY_REQ 		CRYPTO_DIR "my_pc_req"
#define MY_SIG		CRYPTO_DIR "my_signature"
#define RECV_REQ	CRYPTO_DIR "recv_pc_req_"
#define RECV_CERT	CRYPTO_DIR "recv_pc_"
#define ISSUED_CERT	CRYPTO_DIR "issued_pc"

void init_am();







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


typedef struct PROXYCERTINFO_st
{
	ASN1_INTEGER *path_length;       /* [ OPTIONAL ] */
	PROXYPOLICY *policy;
} PROXYCERTINFO;



/*
#define ASN1_F_PROXYPOLICY_NEW          450
#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14" //tester
#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
#define LIMITED_PROXY_SN                "LIMITED_PROXY"
#define LIMITED_PROXY_LN                "GSI limited proxy"
*/


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






/*
 *
 * New ones, in right order
 *
 */

/* Definitions */
#define MAXBUFLEN 1500
#define SUBJECT_NAME_SIZE 16

/* Naming standard structs */
typedef struct addrinfo addrinfo;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr sockaddr;
typedef struct timeval timeval;

/* AM Structs */


/* AM Enums */


/* Functions */
void am_thread_init(char *dev, sockaddr_in addr, sockaddr_in broad);
void *am_main();

void setup_am_socks(int32_t *recv, int32_t *send);
int setup_am_recv_socks(int32_t *recv, addrinfo *res);
int setup_am_send_socks(int32_t *send);
void destroy_am_socks(int32_t *send, int32_t *recv, addrinfo *res);

static void callback(int p, int n, void *arg);

void create_signature();
int create_proxy_cert_0(EVP_PKEY *pkey, unsigned char *subject_name);
int create_proxy_cert_req(EVP_PKEY *pkey, unsigned char *subject_name);
int create_proxy_cert_1(char *addr);

int selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name);
int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name);
int mkcert(X509_REQ **reqp, X509 **pc1p, X509 **pc0p);

int seed_prng(int bytes);

void send_signature();

void send_pc_invite(sockaddr_in *sin_dest);
void send_pc_req(sockaddr_in *sin_dest);
void send_pc_issue(sockaddr_in *sin_dest);

am_type extract_am_header(char *buf, char **ptr);

int receive_pc_req(char *addr, char *ptr);
int receive_pc_issue(char *ptr);




/* Necessary external variables */
extern role_type my_role;
extern pthread_t am_main_thread;
extern uint32_t new_neighbor;
extern uint32_t trusted_neighbors[100];
extern uint8_t num_trusted_neighbors;
extern char signature_extract[3];

#endif
