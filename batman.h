/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef _BATMAN_BATMAN_H
#define _BATMAN_BATMAN_H

#include <netinet/in.h>
#include "list.h"

#define VERSION "0.1"
#define BATMAN_VERSION 1
#define PORT 1966
#define UNIDIRECTIONAL 0xF0
#define ADDR_STR_LEN 16

/*
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with: */

#define BIDIRECT_TO 3000 /* bidirectional neighbour reply timeout in ms */
#define TTL 50 /* Time To Live of broadcast messages */
#define TIMEOUT 30000 /* sliding window size of received orginator messages in ms */




extern int debug_level;
extern int orginator_interval;
extern int gateway_class;
extern int routing_class;
extern unsigned int pref_gateway;

extern int found_ifs;

extern struct list_head if_list;
extern struct vis_if vis_if;

struct packet
{
	unsigned long  orig;
	unsigned char  flags;    /* 0xF0: UNIDIRECTIONAL link, 0x80: ip-gateway, ... */
	unsigned char  ttl;
	unsigned short seqno;
	unsigned short interval; /* in ms until latest next emission */
	unsigned char  gwflags;  /* flags related to gateway functions: gateway class */
	unsigned char  version;  /* batman version field */
} __attribute__((packed));

struct orig_node                 /* structure for orig_list maintaining nodes of mesh */
{
	struct list_head list;
	unsigned int orig;
	unsigned int router;
	struct batman_if *batman_if;
	unsigned int packet_count; /* packets gathered from its router */
	unsigned int last_seen;    /* when last originator packet (with new seq-number) from this node was received */
	unsigned int last_reply;   /* if node is a neighbour, when my originator packet was last broadcasted (replied) by this node and received by me */
	unsigned int last_aware;   /* if node is a neighbour, when last packet via this node was received */
	unsigned short interval;   /* in ms until next emission */
	unsigned char flags;
	unsigned char gwflags;     /* flags related to gateway functions: gateway class */
	struct list_head neigh_list;
};

struct neigh_node
{
	struct list_head list;
	unsigned int addr;
	struct list_head pack_list;
};

struct pack_node
{
	struct list_head list;
	unsigned int time;
	unsigned short seqno;
	unsigned char ttl;
	struct batman_if *if_incoming;
};

struct forw_node                 /* structure for forw_list maintaining packets to be send/forwarded */
{
	struct list_head list;
	unsigned int when;
	struct packet pack;
};

struct gw_node
{
	struct list_head list;
	struct orig_node *orig_node;
};

struct batman_if
{
	struct list_head list;
	char *dev;
	int udp_send_sock;
	int udp_recv_sock;
	int tcp_gw_sock;
	int if_num;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	struct packet out;
};

struct vis_if {
	int sock;
	struct sockaddr_in addr;
};

/*
static void update_routes();
static void debug();
*/


int batman();
void usage(void);
void verbose_usage(void);

#endif
