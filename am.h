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
#include <time.h>

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






//typedef struct {
//	ASN1_OBJECT *policyLanguage;
//	ASN1_OCTET_STRING *policy;
//} ProxyPolicy;
//
//typedef struct {
//	ASN1_INTEGER *pCPathLenConstraint;
//	ProxyPolicy *proxyPolicy;
//} ProxyCertInfoExtension;
//
//typedef struct PROXYPOLICY_st
//{
//	ASN1_OBJECT *policy_language;
//	ASN1_OCTET_STRING *policy;
//} PROXYPOLICY;
//
//
//typedef struct PROXYCERTINFO_st
//{
//	ASN1_INTEGER *path_length;       /* [ OPTIONAL ] */
//	PROXYPOLICY *policy;
//} PROXYCERTINFO;
//
//
//#define ASN1_F_PROXYPOLICY_NEW          450
//#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14" //tester
//#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
//#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
//#define LIMITED_PROXY_SN                "LIMITED_PROXY"
//#define LIMITED_PROXY_LN                "GSI limited proxy"











/*
 * TEMP
 */
void dump_memory(void* data, size_t len);



/*
 * MAYBE
 */
typedef struct invite_pc_packet_st {
	uint8_t key_algorithm;
	uint16_t key_size;
} __attribute__((packed)) invite_pc_packet;

typedef enum key_algorithm_en{
	ECC_key = 1,
	RSA_key = 2
} key_algorithm;



/*
 *
 * TO KEEP!!!
 *
 */

/* Definitions */
#define IF_NAMESIZE			16
#define AM_PORT 			64305
#define MAXBUFLEN 			1500
#define SUBJECT_NAME_SIZE 	16
#define AES_BLOCK_SIZE 		16
#define AES_KEY_SIZE 		16
#define AES_IV_SIZE 		16
#define RAND_LEN 			(AES_BLOCK_SIZE*64)-1

#define CRYPTO_DIR			"./tmp_crypto/"
#define MY_KEY				CRYPTO_DIR "my_private_key"
#define MY_CERT				CRYPTO_DIR "my_pc"
#define MY_REQ 				CRYPTO_DIR "my_pc_req"
#define MY_RAND				CRYPTO_DIR "my_rand"
#define MY_SIG				CRYPTO_DIR "my_sig"
#define RECV_REQ			CRYPTO_DIR "recv_pc_req_"
#define RECV_CERT			CRYPTO_DIR "recv_pc_"
#define ISSUED_CERT			CRYPTO_DIR "issued_pc"

/* Naming standard structs */
typedef struct addrinfo addrinfo;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr sockaddr;
typedef struct in_addr in_addr;
typedef struct timeval timeval;

/* AM Structs */
typedef struct am_packet_st {
	uint16_t id;
	uint8_t type;
} __attribute__((packed)) am_packet;

typedef struct routing_auth_packet_st {
	unsigned char rand[RAND_LEN];
	unsigned char key[AES_KEY_SIZE];
	unsigned char iv[AES_IV_SIZE];
}__attribute__((packed)) routing_auth_packet;



/* AM Enums */
typedef enum am_state_en {
	READY,
	SEND_INVITE,
	WAIT_FOR_REQ,
	SEND_REQ,
	WAIT_FOR_PC,
	SEND_PC,
	SENDING_NEW_SIGS,
	SENDING_SIG
} am_state;

typedef enum am_type_en{
	SIGNATURE,
	AL_FULL,
	AL_ROW,
	AUTH_INVITE,
	AUTH_REQ,
	AUTH_ISSUE,
	AUTH_ACK,
	NEIGH_PC,
	NEIGH_SIGN,
	NEIGH_PC_REQ,
	NEIGH_SIG_REQ
} am_type;

typedef enum role_type_en{
	UNAUTHENTICATED,
	AUTHENTICATED,
	MASTER,
	SP
} role_type;




/* Functions */
void am_thread_init(char *dev, sockaddr_in addr, sockaddr_in broad);
void *am_main();

void setup_am_socks(int32_t *recv, int32_t *send);
int setup_am_recv_socks(int32_t *recv, addrinfo *res);
int setup_am_send_socks(int32_t *send);
void destroy_am_socks(int32_t *send, int32_t *recv, addrinfo *res);

static void openssl_callback(int p, int n, void *arg);

void create_signature();
int create_proxy_cert_0(EVP_PKEY *pkey, unsigned char *subject_name);
int create_proxy_cert_req(EVP_PKEY *pkey, unsigned char *subject_name);
int create_proxy_cert_1(char *addr);

int selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name);
int mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name);
int mkcert(X509_REQ **reqp, X509 **pc1p, X509 **pc0p);

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);

int seed_prng(int bytes);

void send_signature();

void send_pc_invite(sockaddr_in *sin_dest);
void send_pc_req(sockaddr_in *sin_dest);
void send_pc_issue(sockaddr_in *sin_dest);

void broadcast_signature_packet(EVP_CIPHER_CTX *master, int *key_count, routing_auth_packet **payload);
void send_signature_packet();

am_type extract_am_header(char *buf, char **ptr);

int receive_pc_req(char *addr, char *ptr);
int receive_pc_issue(char *ptr);
int receive_routing_auth_packet(char *ptr);


unsigned char *generate_new_key(EVP_CIPHER_CTX *aes_master, int key_count);
void generate_new_rand(unsigned char **rand, int len);

void select_random_key(unsigned char **key, int b);
void select_random_iv(unsigned char **iv, int b);
int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

void init_master_ctx(EVP_CIPHER_CTX *master);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);




/* Necessary external variables */
extern role_type my_role;
extern am_state my_state;
extern pthread_t am_main_thread;
extern uint32_t new_neighbor;
extern uint32_t trusted_neighbors[100];
extern uint8_t num_trusted_neighbors;
extern unsigned char *auth_value;
extern uint8_t auth_seq_num;

#endif
