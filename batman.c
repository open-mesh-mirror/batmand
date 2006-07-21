/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann,
 * Felix Fietkau
 *
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "os.h"
#include "batman.h"
#include "list.h"

/* "-d" is the command line switch for the debug level,
 * specify it multiple times to increase verbosity
 * 0 gives a minimum of messages to save CPU-Power
 * 1 normal
 * 2 verbose 
 * 3 very verbose
 * Beware that high debugging levels eat a lot of CPU-Power
 */
 
int debug_level = 0;

int orginator_interval = 1000; /* orginator message interval in miliseconds */
#define UNIDIRECTIONAL 0xF0
#define ADDR_STR_LEN 16


struct packet
{
	unsigned long  orig;
	unsigned char  flags;    /* 0xF0: UNIDIRECTIONAL link, 0x80: ip-gateway, ... */
	unsigned char  ttl;
	unsigned short seqno;    
	unsigned short interval; /* in ms until latest next emission */
} __attribute__((packed));

struct orig_node
{
	struct list_head list;
	unsigned int orig;
	unsigned int router;
	unsigned int last_seen;    /* when last originator packet (with new seq-number) from this node was received */
	unsigned int last_reply;   /* if node is a neighbour, when my originator packet was last broadcasted (replied) by this node and received by me */
	unsigned int last_aware;   /* if node is a neighbour, when last packet via this node was received */
	unsigned short interval;   /* in ms until next emission */
	unsigned char flags;
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
};

struct forw_node
{
	struct list_head list;
	unsigned int when;
	struct packet pack;
};


static LIST_HEAD(orig_list);
static LIST_HEAD(forw_list);
static unsigned int next_own;
static unsigned int my_addr;

static struct packet out;




/* this function finds or creates an originator entry for the given address if it does not exits */
struct orig_node *get_orig_node( unsigned int addr )
{
	struct list_head *pos;
	struct orig_node *orig_node;

	list_for_each(pos, &orig_list) {
		orig_node = list_entry(pos, struct orig_node, list);
		if (orig_node->orig == addr)
			return orig_node;
	}
	
	if (debug_level >= 2) 
		output("Creating new originator\n");
	
	orig_node = alloc_memory(sizeof(struct orig_node));
	memset(orig_node, 0, sizeof(struct orig_node));
	INIT_LIST_HEAD(&orig_node->list);
	INIT_LIST_HEAD(&orig_node->neigh_list);
	
	orig_node->orig = addr;
	
	list_add_tail(&orig_node->list, &orig_list);
	
	return orig_node;
}




static void update_routes()
{
	struct list_head *orig_pos, *neigh_pos, *pack_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node, *next_hop;
	struct pack_node *pack_node;
	int max_pack, max_ttl, neigh_ttl, neigh_pkts;
	static char orig_str[ADDR_STR_LEN], next_str[ADDR_STR_LEN];

	if (debug_level >= 2)
		output("update_routes() \n");

	/* for every origin... */
	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

		max_ttl  = 0;
		max_pack = 0;
		next_hop = NULL;

		/* for every neighbour... */
		list_for_each(neigh_pos, &orig_node->neigh_list) {
			neigh_node = list_entry(neigh_pos, struct neigh_node, list);
					
			neigh_ttl = 0;
			neigh_pkts = 0;

			list_for_each(pack_pos, &neigh_node->pack_list) {
				pack_node = list_entry(pack_pos, struct pack_node, list);
				if (pack_node->ttl > neigh_ttl)
					neigh_ttl = pack_node->ttl;

				neigh_pkts++;
			}

			/* if received most orig_packets via this neighbour (or ) then 
		 		select this neighbour as next hop for this origin */ 
			if ((neigh_pkts > max_pack) || ((neigh_pkts > max_pack) && (neigh_ttl > max_ttl))) {
				max_pack = neigh_pkts;
				max_ttl = neigh_ttl;
				
				next_hop = neigh_node;
				if (debug_level >= 2) 
					output("%d living received packets via selected router \n", neigh_pkts );
			}
		}
		
		if (next_hop != NULL) {
			if (debug_level >= 2) {
				addr_to_string(orig_node->orig, orig_str, ADDR_STR_LEN);
				addr_to_string(next_hop->addr, next_str, ADDR_STR_LEN);
		
				output("Route to %s via %s\n", orig_str, next_str);
			}

		
			if (orig_node->router != next_hop->addr) {
				if (debug_level >= 2)
				output("Route changed\n");
			
				if (orig_node->router != 0) {
					if (debug_level >= 2) 
						output("Deleting previous route\n");

					add_del_route(orig_node->orig, orig_node->router, 1);
				}
			
				if (debug_level >= 2) { output("Adding new route\n");  }
			
			
				/* TODO: maybe the order delete, add should be changed ???? */
				add_del_route(orig_node->orig, next_hop->addr, 0);
			
				orig_node->router = next_hop->addr;
			}
		}
	}
}

static void debug()
{
	struct list_head *forw_pos, *orig_pos, *neigh_pos, *pack_pos, *temp;
	struct forw_node *forw_node;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct pack_node *pack_node;
	static char str[ADDR_STR_LEN];
	int l;

	if (debug_level < 1) 
		return;

	if (debug_level >= 2) {
		output("------------------ DEBUG ------------------\n");
		output("Forward list\n");  

		list_for_each(forw_pos, &forw_list) {
			forw_node = list_entry(forw_pos, struct forw_node, list);
			addr_to_string(forw_node->pack.orig, str, sizeof (str));
			output("    %s at %u\n", str, forw_node->when);
		}
		

		output("Originator list\n");
	}
	
	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);
		
		addr_to_string(orig_node->orig, str, sizeof (str));
		
		output("%s, last_aware:%u, last_reply:%u, last_seen:%u via:\n",
				 str, orig_node->last_aware, orig_node->last_reply, orig_node->last_seen); 
			
		list_for_each(neigh_pos, &orig_node->neigh_list) {
			neigh_node = list_entry(neigh_pos, struct neigh_node, list);
			
			l = 0;
			list_for_each(temp, &neigh_node->pack_list) {
				l++;
			}

			if (debug_level >= 2) {
				addr_to_string(neigh_node->addr, str, sizeof (str));
				output("\t\t%s (%d)\n", str, l);
			}
			
			if (debug_level >= 3) {
				list_for_each(pack_pos, &neigh_node->pack_list) {
					pack_node = list_entry(pack_pos, struct pack_node, list);
					output("        Sequence number: %d, TTL: %d at: %u \n",
							pack_node->seqno, pack_node->ttl, pack_node->time);
				}    
			}
		}
	}
	
	if (debug_level >= 2) 
		output("---------------------------------------------- END DEBUG\n");
}

int isDuplicate(unsigned int orig, unsigned short seqno)
{
	struct list_head *orig_pos, *neigh_pos, *pack_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct pack_node *pack_node;

/* 	if (debug_level >= 2)  {  output("isDuplicate(): every originator \n");  } */
	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

/* 		if (debug_level >= 2)  {  output("isDuplicate(): every neighbour \n");  } */
		list_for_each(neigh_pos, &orig_node->neigh_list) {
			neigh_node = list_entry(neigh_pos, struct neigh_node, list);

/*     		if (debug_level >= 2)  {  output("isDuplicate(): every packet \n");  } */
			
			list_for_each(pack_pos, &neigh_node->pack_list) {
				pack_node = list_entry(pack_pos, struct pack_node, list);

				if (orig_node->orig == orig && pack_node->seqno == seqno){
/* 					if (debug_level >= 2)  {  output("isDuplicate(): YES \n");  } */
					return 1;
				}
			}
		}
	}

/* 	if (debug_level >= 2)  {  output("isDuplicate(): NO \n");  } */
	return 0;
}

int isBidirectionalNeigh( struct orig_node *orig_neigh_node )
{
	if( orig_neigh_node->last_reply > 0 && (orig_neigh_node->last_reply + (BIDIRECT_TO)) >= get_time() )
		return 1;
	else return 0;
}

int hasUnidirectionalFlag( struct packet *in )
{
	if( in->flags & UNIDIRECTIONAL ) 
		return 1;
	else return 0;
}



struct orig_node *update_last_hop(struct packet *in, unsigned int neigh)
{
	struct orig_node *orig_neigh_node;

	if (debug_level >= 2) { 
		output("update_last_hop(): Searching originator entry of last-hop neighbour of received packet \n"); }
	orig_neigh_node = get_orig_node( neigh );
	orig_neigh_node->last_aware = get_time();

	if (neigh != my_addr && in->orig == my_addr && in->ttl == TTL-1)	{
		if (debug_level >= 2)	{	
			output("received my own packet from neighbour indicating bidirectional link, updating last_reply stamp \n");  
		}
		orig_neigh_node->last_reply = get_time();
	}

	return orig_neigh_node;

}

void update_originator(struct packet *in, unsigned int neigh)
{
	struct list_head *neigh_pos, *pack_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node = NULL;
	struct pack_node *pack_node = NULL;

	if (debug_level >= 2)
		output("update_originator(): Searching and updating originator entry of received packet,  \n");
	
	orig_node = get_orig_node( in->orig );

	orig_node->last_seen = get_time();
	orig_node->interval = in->interval;
	orig_node->flags = in->flags;

	list_for_each(neigh_pos, &orig_node->neigh_list) {
		neigh_node = list_entry(neigh_pos, struct neigh_node, list);
		
		if (neigh_node->addr != neigh)
			neigh_node = NULL;
	}

	if (neigh_node == NULL)  {
		if (debug_level >= 2)
			output("Creating new last-hop neighbour of originator\n");

		neigh_node = alloc_memory(sizeof (struct neigh_node));
		INIT_LIST_HEAD(&neigh_node->list);
		INIT_LIST_HEAD(&neigh_node->pack_list);

		neigh_node->addr = neigh;

		list_add_tail(&neigh_node->list, &orig_node->neigh_list);
	} else if (debug_level >= 2) 
		output("Updating existing last-hop neighbour of originator\n");

	list_for_each(pack_pos, &neigh_node->pack_list) {
		pack_node = list_entry(pack_pos, struct pack_node, list);

		if (pack_node->seqno != in->seqno)
			pack_node = NULL;
	}
	
	if (pack_node == NULL)  {
		if (debug_level >= 2)
			output("Creating new packet entry for last-hop neighbor of originator \n");

		pack_node = alloc_memory(sizeof (struct pack_node));
		INIT_LIST_HEAD(&pack_node->list);

		pack_node->seqno = in->seqno;
		list_add_tail(&pack_node->list, &neigh_node->pack_list);
	} else
		output("ERROR - Updating existing packet\n");
	
	pack_node->ttl = in->ttl;
	pack_node->time = get_time();

	update_routes();
}

void schedule_forward_packet( struct packet *in, int unidirectional)
{
	struct forw_node *forw_node, *forw_node_new;
	struct list_head *forw_pos;

	if (debug_level >= 2)
		output("schedule_forward_packet():  \n");
	
	if (in->ttl <= 1) {
		if (debug_level >= 2)
			output("ttl exceeded \n");
	} else {
		forw_node_new = alloc_memory(sizeof (struct forw_node));
		INIT_LIST_HEAD(&forw_node_new->list);

		memcpy(&forw_node_new->pack, in, sizeof (struct packet));
		
		forw_node_new->pack.ttl--;
		
		if (unidirectional) {
			if (debug_level >= 2)
				output("sending with unidirectional flag \n");

			forw_node_new->pack.flags = (forw_node_new->pack.flags | UNIDIRECTIONAL);
		}
		
		forw_node_new->when = get_time() + rand_num(JITTER);
		
		list_for_each(forw_pos, &forw_list) {
			forw_node = list_entry(forw_pos, struct forw_node, list);
			if ((int)(forw_node->when - forw_node_new->when) > 0)
				break;
		}
		
		list_add(&forw_node_new->list, &forw_list);
	}
}

void send_outstanding_packets()
{
	struct forw_node *forw_node;
	struct list_head *forw_pos, *temp;
	struct packet *pack;
	static char orig_str[ADDR_STR_LEN];

	if (list_empty(&forw_list))
		return;

	list_for_each_safe(forw_pos, temp, &forw_list) {
		forw_node = list_entry(forw_pos, struct forw_node, list);

		if (forw_node->when <= get_time())
		{
			pack = &forw_node->pack;

			if (debug_level >= 2) { 
				addr_to_string(pack->orig, orig_str, ADDR_STR_LEN);
				output("Forwarding packet (originator %s, seqno %d, TTL %d)\n",
						 orig_str, pack->seqno, pack->ttl);	
			}
		
			if (send_packet((unsigned char *)pack, sizeof (struct packet)) < 0) {
				output("ERROR: send_packet returned -1 \n");
				exit( -1);
			}
			
			list_del(forw_pos);
			free_memory(forw_node);
		}
	}
}

void schedule_own_packet() {
	int queue_own = 1;
	struct forw_node *forw_node = NULL, *forw_node_new;
	struct list_head *forw_pos;

	list_for_each(forw_pos, &forw_list) {
		forw_node = list_entry(forw_pos, struct forw_node, list);
		break;
	}
	
	if (forw_node != NULL)
	{
		if ((int)(forw_node->when - next_own) < 0)
			queue_own = 0;
	}

	if (queue_own != 0) {
		forw_node_new = alloc_memory(sizeof (struct forw_node));
		INIT_LIST_HEAD(&forw_node_new->list);

		memcpy(&forw_node_new->pack, &out, sizeof (struct packet));
		forw_node_new->when = next_own;

		list_add(&forw_node_new->list, (forw_node == NULL ? &forw_list : forw_pos));

		next_own += orginator_interval - JITTER + rand_num(2 * JITTER);
		out.seqno++;
	}
}

void purge()
{
	struct list_head *orig_pos, *neigh_pos, *pack_pos, *orig_temp, *neigh_temp, *pack_temp;	
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct pack_node *pack_node;
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];

	if (debug_level >= 2)
		output("purge() \n");
	
	/* for all origins... */
	list_for_each_safe(orig_pos, orig_temp, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

		/* for all neighbours towards the origins... */
		list_for_each_safe(neigh_pos, neigh_temp, &orig_node->neigh_list) {
			neigh_node = list_entry(neigh_pos, struct neigh_node, list);

			/* for all packets from the origins via this neighbours... */
			list_for_each_safe(pack_pos, pack_temp, &neigh_node->pack_list) {
				pack_node = list_entry(pack_pos, struct pack_node, list);

				/* remove them if outdated */
				if ((int)((pack_node->time + TIMEOUT) < get_time()))
				{
					if (debug_level >= 2) {
						addr_to_string(orig_node->orig, orig_str, ADDR_STR_LEN);
						addr_to_string(neigh_node->addr, neigh_str, ADDR_STR_LEN);
						output("Packet timeout (originator %s, neighbour %s, seqno %d, TTL %d, time %u)\n",
						     orig_str, neigh_str, pack_node->seqno, pack_node->ttl, pack_node->time);
					}
					list_del(pack_pos);
					free_memory(pack_node);
				}
			}

			/* if no more packets, remove neighbour (next hop) towards given origin */
			if (list_empty(&neigh_node->pack_list)) {
				if (debug_level >= 2) {
					addr_to_string(neigh_node->addr, neigh_str, sizeof (neigh_str));
					addr_to_string(orig_node->orig, orig_str, sizeof (orig_str));
					output("Removing orphaned neighbour %s for originator %s\n", neigh_str, orig_str);
				}
				list_del(neigh_pos);
				free_memory(neigh_node);
			}
		}

		/* if no more neighbours (next hops) towards given origin, remove origin */
		if (list_empty(&orig_node->neigh_list) && ((int)(orig_node->last_aware) + TIMEOUT <= ((int)(get_time())))) {
			if (debug_level >= 2) {
				addr_to_string(orig_node->orig, orig_str, sizeof (orig_str));
				output("Removing orphaned originator %s\n", orig_str);
			}
			list_del(orig_pos);

			if (debug_level >= 2)
				output("Deleting route to originator \n");

			add_del_route(orig_node->orig, 0, 1);
			free_memory(orig_node);
		}
	}

	update_routes();
}




int batman(unsigned int addr_parm)
{
	struct list_head *forw_pos, *orig_pos;
	struct forw_node *forw_node;
	struct orig_node *orig_node, *orig_neigh_node;
	struct packet in;
	int res;
	unsigned int neigh;
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
	int forward_old;

	next_own = 0;
	my_addr = addr_parm;

	out.orig = my_addr;
	out.flags = 0x00;
	out.ttl = TTL;
	out.seqno = 0;
	out.interval = orginator_interval + JITTER;

	forward_old = get_forwarding();
	set_forwarding(1);

	while (!is_aborted())
	{
		if (debug_level >= 2)
			output(" \n \n");

		schedule_own_packet();

		list_for_each(forw_pos, &forw_list) {
			forw_node = list_entry(forw_pos, struct forw_node, list);
			res = receive_packet((unsigned char *)&in, sizeof (struct packet), &neigh, forw_node->when);
			break;
		}

		if (res < 0) 
			return -1;

		if (res > 0)
		{
			if (debug_level >= 3)  {
				addr_to_string(in.orig, orig_str, sizeof (orig_str));
				addr_to_string(neigh, neigh_str, sizeof (neigh_str));
				output("Received BATMAN packet from %s (originator %s, seqno %d, TTL %d)\n", neigh_str, orig_str, in.seqno, in.ttl);       
			}
				
			if (neigh == my_addr /* && in.orig == my_addr */) {
				if (debug_level >= 3)
					output("Ignoring all (zero-hop) packets send by me \n");
					
			} else {
				orig_neigh_node = update_last_hop( &in, neigh );
	
				if (debug_level >= 2) {
					if (isDuplicate(in.orig, in.seqno)) 
						output("Duplicate packet \n");
					
					if ( in.orig == neigh )
						output("Originator packet from neighbour \n");

					if ( in.orig == my_addr )
						output("Originator packet from myself (via neighbour) \n");

					if ( in.flags & UNIDIRECTIONAL )
						output("Packet with unidirectional flag \n");

					if ( isBidirectionalNeigh( orig_neigh_node ) )
						output("received via bidirectional link \n");
				}


				if( in.orig == neigh && in.ttl == TTL &&
						!isBidirectionalNeigh( orig_neigh_node )  && 
						!isDuplicate(in.orig, in.seqno) &&
						!(in.flags & UNIDIRECTIONAL) ) {
						
					schedule_forward_packet(&in, 1);
					
				} else if ( in.orig == neigh && in.ttl == TTL &&
						isBidirectionalNeigh( orig_neigh_node )  && 
						!isDuplicate(in.orig, in.seqno) &&
						!(in.flags & UNIDIRECTIONAL) ) {
						
					update_originator( &in, neigh );
					schedule_forward_packet(&in, 0);
					
				} else if ( in.orig != neigh && in.orig != my_addr &&
						isBidirectionalNeigh( orig_neigh_node )  && 
						!isDuplicate(in.orig, in.seqno) &&
						!(in.flags & UNIDIRECTIONAL) ) {
						
					update_originator( &in, neigh );
					schedule_forward_packet(&in, 0);
						
				} else {
					if (debug_level >= 3)
						output("Ignoring packet... \n");
				}
			}
		}
		send_outstanding_packets(); 
		
		purge();
		debug();
	}
	
	output("Deleting all BATMAN routes\n");

	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

		if (orig_node->router != 0)
			add_del_route(orig_node->orig, orig_node->router, 1);
	}

	set_forwarding(forward_old);
	
	return 0;
}
