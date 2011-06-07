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

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
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
void tool_dump_memory(unsigned char *data, size_t len);



/*
 * MAYBE
 */

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
#define MAXBUFLEN 			1500-20-8 //MTU - IP_HEADER - UDP_HEADER
#define SUBJECT_NAME_SIZE 	16
#define FULL_SUB_NM_SZ		3*SUBJECT_NAME_SIZE
#define AES_BLOCK_SIZE 		16
#define AES_KEY_SIZE 		16
#define AES_IV_SIZE 		16
#define RAND_LEN 			(AES_BLOCK_SIZE*48)-1	//Chosen so auth_packets are well below MAXBUFLEN

#define CRYPTO_DIR			"./.crypto/"
#define MY_KEY				CRYPTO_DIR "my_private_key"
#define MY_CERT				CRYPTO_DIR "my_pc"
#define MY_REQ 				CRYPTO_DIR "my_pc_req"
#define MY_RAND				CRYPTO_DIR "my_rand"
#define MY_SIG				CRYPTO_DIR "my_sig"
#define RECV_REQ			CRYPTO_DIR "recv_pc_req_"
#define RECV_CERT			CRYPTO_DIR "recv_pc_"
#define ISSUED_CERT			CRYPTO_DIR "issued_pc"
#define SP_CERT				CRYPTO_DIR "sp_pc"

#define RSA_KEY_SIZE		1024
//#define ECC_CURVE			NID_sect163k1
#define ECC_CURVE			NID_secp160r1
//#define ECIES_CURVE NID_secp521r1
#define ECDH_CIPHER 		EVP_aes_128_cbc()
#define ECDH_HASHER 		EVP_sha256()

/* Naming standard structs */
typedef struct addrinfo addrinfo;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr sockaddr;
typedef struct in_addr in_addr;
typedef struct timeval timeval;


/* AM Structs */

typedef char * secure_t;
typedef struct {

struct {
uint32_t key;
uint32_t mac;
uint32_t orig;
uint32_t body;
} length;

} secure_head_t;

typedef struct trusted_node_st {
	uint16_t 		id;			//unique
	uint32_t		addr;		//unique ip addr
	uint8_t			role;		//SP, AUTH or whatever (might use proxypolicy rules)
	unsigned char	*name;		//Unique PC subject name
	EVP_PKEY 		*pub_key;	//Public Key of node

} trusted_node;

typedef struct trusted_neigh_st {
	uint16_t 		id;				//unique
	uint32_t		addr;			//unique ip addr
	uint64_t		window;			//Sliding window, if a bit is set 0 that pkt not received, else received
	uint16_t		last_seq_num;	//Used with sliding windows
	unsigned char	*mac;			//Message Authentication Code (current)
	time_t 			last_rcvd_time;
} trusted_neigh;

typedef struct am_packet_st {
	uint16_t 	id;
	uint8_t 	type;
} __attribute__((packed)) am_packet;

typedef struct routing_auth_packet_st {
	uint16_t 	rand_len;
	uint8_t 	iv_len;
	uint8_t		sign_len;
//	uint8_t 	key_len;
}__attribute__((packed)) routing_auth_packet;

//typedef struct routing_auth_packet_st {
//	unsigned char rand[RAND_LEN*(4/3)+3];
//	unsigned char key[AES_KEY_SIZE];
//	unsigned char iv[AES_IV_SIZE];
//}__attribute__((packed)) routing_auth_packet;



/* AM Enums */
typedef enum am_state_en {
	READY,
	SEND_INVITE,
	WAIT_FOR_REQ,
	SEND_REQ,
	WAIT_FOR_PC,
	SEND_PC,
	SENDING_NEW_SIGS,
	SENDING_SIG,
	WAIT_FOR_NEIGH_SIG,
	WAIT_FOR_NEIGH_PC,
	WAIT_FOR_NEIGH_SIG_ACK	//special for SP waiting for sign as "ACK" after ISSUE
} am_state;

typedef enum am_type_en{
	NO_AM_DATA,
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
	RESTRICTED,
	MASTER,
	SP
} role_type;




/* Functions */
void am_thread_init(char *dev, sockaddr_in addr, sockaddr_in broad);
void am_thread_kill();
void *am_main();

void socks_am_setup(int32_t *recv, int32_t *send);
int socks_recv_setup(int32_t *recv, addrinfo *res);
int socks_send_setup(int32_t *send);
void socks_am_destroy(int32_t *send, int32_t *recv);

static void openssl_tool_callback(int p, int n, void *arg);

void create_signature();
int openssl_cert_create_pc0(EVP_PKEY **pkey, unsigned char **subject_name);
int openssl_cert_create_req(EVP_PKEY **pkey, unsigned char *subject_name);
int openssl_cert_create_pc1(EVP_PKEY **pkey, char *addr, unsigned char **subject_name);

int openssl_cert_selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char **subject_name);
int openssl_cert_mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char *subject_name);
int openssl_cert_mkcert(EVP_PKEY **pkey, X509_REQ *reqp, X509 **pc1p, X509 **pc0p, unsigned char **subject_name);

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);

int openssl_tool_seed_prng(int bytes);void *KDF1_SHA256(const void *in, size_t inlen, void *out, size_t *outlen);

void send_signature();

void auth_invite_send(sockaddr_in *sin_dest);
void auth_request_send(sockaddr_in *sin_dest);
void auth_issue_send(sockaddr_in *sin_dest);

char *all_sign_send(EVP_PKEY *pkey, EVP_CIPHER_CTX *master, int *key_count);
void neigh_sign_send(EVP_PKEY *pkey, sockaddr_in *addr, char *buf);
void neigh_req_pc_send(sockaddr_in *neigh_addr);
void neigh_pc_send(sockaddr_in *sin_dest);

am_type am_header_extract(char *buf, char **ptr, int *id);

int auth_request_recv(char *addr, char *ptr);
int auth_issue_recv(char *ptr);
int auth_invite_recv(char *ptr);

int neigh_sign_recv(EVP_PKEY *pkey, uint32_t addr, uint16_t id, char *ptr);
int neigh_pc_recv(in_addr addr, char *ptr);


unsigned char *openssl_key_generate(EVP_CIPHER_CTX *aes_master, int key_count);
void openssl_tool_gen_rand(unsigned char **rand, int len);

void openssl_key_master_select(unsigned char **key, int b);
void openssl_key_iv_select(unsigned char **iv, int b);
int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

void openssl_key_master_ctx(EVP_CIPHER_CTX *master);
unsigned char *openssl_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

void al_add(uint32_t addr, uint16_t id, role_type role, unsigned char *subject_name, EVP_PKEY *key);
void neigh_list_add(uint32_t addr, uint16_t id, unsigned char *mac_value);

EVP_PKEY *openssl_key_copy(EVP_PKEY *key);
int openssl_cert_read(in_addr addr, unsigned char **s, EVP_PKEY **p);

int tool_sliding_window(uint16_t seq_num, uint16_t id);

char * tool_base64_encode(unsigned char * input, int length);
unsigned char * tool_base64_decode(char * input, int in_length, int *out_length);

void *KDF1_SHA256(const void *in, size_t inlen, void *out, size_t *outlen);


/* Necessary external variables */
extern role_type my_role, req_role;
extern am_state my_state;
extern pthread_t am_main_thread;
extern uint32_t new_neighbor;
extern uint32_t trusted_neighbors[100];
extern unsigned char *auth_value;
extern uint16_t auth_seq_num;
extern pthread_mutex_t auth_lock;
extern int num_auth_nodes;
extern int num_trusted_neigh;

extern trusted_neigh *neigh_list[100];

#endif
