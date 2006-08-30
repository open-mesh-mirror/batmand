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
#include "list.h"
#include "batman.h"

/* "-d" is the command line switch for the debug level,
 * specify it multiple times to increase verbosity
 * 0 gives a minimum of messages to save CPU-Power
 * 1 normal
 * 2 verbose
 * 3 very verbose
 * Beware that high debugging levels eat a lot of CPU-Power
 */

int debug_level = 0;

/* "-g" is the command line switch for the gateway class,
 * 0 no gateway
 * 1 modem
 * 2 ISDN
 * 3 Double ISDN
 * 3 256 KBit
 * 5 UMTS/ 0.5 MBit
 * 6 1 MBit
 * 7 2 MBit
 * 8 3 MBit
 * 9 5 MBit
 * 10 6 MBit
 * 11 >6 MBit
 * this option is used to determine packet path
 */

int gateway_class = 0;

/* "-r" is the command line switch for the routing class,
 * 0 set no default route
 * 1 use fast internet connection
 * 2 use stable internet connection
 * 3 use use best statistic (olsr style)
 * this option is used to set the routing behaviour
 */

int routing_class = 0;


int orginator_interval = 1000; /* orginator message interval in miliseconds */

struct gw_node *curr_gateway = NULL;
unsigned int pref_gateway = 0;
int found_ifs = 0;



static LIST_HEAD(orig_list);
static LIST_HEAD(forw_list);
static LIST_HEAD(gw_list);
LIST_HEAD(if_list);
static unsigned int next_own;



void usage(void)
{
	fprintf(stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf(stderr, "       -d debug level\n" );
	fprintf(stderr, "       -g gateway class\n" );
	fprintf(stderr, "       -h this help\n" );
	fprintf(stderr, "       -H verbose help\n" );
	fprintf(stderr, "       -o orginator interval in ms\n" );
	fprintf(stderr, "       -p preferred gateway\n" );
	fprintf(stderr, "       -r routing class\n" );
	fprintf(stderr, "       -s visualisation server\n" );
}

void verbose_usage(void)
{
	fprintf(stderr, "Usage: batman [options] interface [interface interface]\n\n" );
	fprintf(stderr, "       -d debug level\n" );
	fprintf(stderr, "          default: 0, allowed values: 0 - 3\n\n" );
	fprintf(stderr, "       -g gateway class\n" );
	fprintf(stderr, "          default:         0 -> this is not an internet gateway\n" );
	fprintf(stderr, "          allowed values:  1 -> modem line\n" );
	fprintf(stderr, "                           2 -> ISDN line\n" );
	fprintf(stderr, "                           3 -> double ISDN\n" );
	fprintf(stderr, "                           4 -> 256 KBit\n" );
	fprintf(stderr, "                           5 -> UMTS / 0.5 MBit\n" );
	fprintf(stderr, "                           6 -> 1 MBit\n" );
	fprintf(stderr, "                           7 -> 2 MBit\n" );
	fprintf(stderr, "                           8 -> 3 MBit\n" );
	fprintf(stderr, "                           9 -> 5 MBit\n" );
	fprintf(stderr, "                          10 -> 6 MBit\n" );
	fprintf(stderr, "                          11 -> >6 MBit\n\n" );
	fprintf(stderr, "       -h shorter help\n" );
	fprintf(stderr, "       -H this help\n" );
	fprintf(stderr, "       -o orginator interval in ms\n" );
	fprintf(stderr, "          default: 1000, allowed values: >0\n\n" );
	fprintf(stderr, "       -p preferred gateway\n" );
	fprintf(stderr, "          default: none, allowed values: IP\n\n" );
	fprintf(stderr, "       -r routing class (only needed if gateway class = 0)\n" );
	fprintf(stderr, "          default:         0 -> set no default route\n" );
	fprintf(stderr, "          allowed values:  1 -> use fast internet connection\n" );
	fprintf(stderr, "                           2 -> use stable internet connection\n" );
	fprintf(stderr, "                           3 -> use best statistic internet connection (olsr style)\n\n" );
	fprintf(stderr, "       -s visualisation server\n" );
	fprintf(stderr, "          default: none, allowed values: IP\n\n" );

}

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
	orig_node->gwflags = 0;
	orig_node->packet_count = 0;

	list_add_tail(&orig_node->list, &orig_list);

	return orig_node;
}



static void choose_gw()
{
	struct list_head *pos;
	struct gw_node *gw_node, *tmp_curr_gw;
	int max_gw_class = 0, max_packets = 0, max_gw_factor = 0;
	static char orig_str[ADDR_STR_LEN];


	if ( routing_class == 0 ) return;

	if ( list_empty(&gw_list) ) {

		if ( curr_gateway != NULL ) {

			if (debug_level >= 0) output( "Removing default route - no gateway in range\n" );

			/* TODO remove default route */

			curr_gateway = NULL;

		}

		return;

	}


	list_for_each(pos, &gw_list) {

		gw_node = list_entry(pos, struct gw_node, list);

		switch ( routing_class ) {

			case 1:   /* fast connection */
				if ( ( gw_node->orig_node->gwflags > max_gw_class ) || ( ( gw_node->orig_node->gwflags == max_gw_class ) && ( gw_node->orig_node->packet_count > max_packets ) ) ) tmp_curr_gw = gw_node;
				break;

			case 2:   /* stable connection */
				if ( ( ( gw_node->orig_node->packet_count * gw_node->orig_node->gwflags ) > max_gw_factor ) || ( ( ( gw_node->orig_node->packet_count * gw_node->orig_node->gwflags ) == max_gw_factor ) && ( gw_node->orig_node->packet_count > max_packets ) ) ) tmp_curr_gw = gw_node;
				break;

			default:  /* use best statistic (olsr style) */
				if ( gw_node->orig_node->packet_count > max_packets ) tmp_curr_gw = gw_node;
				break;

		}

		if ( gw_node->orig_node->gwflags > max_gw_class ) max_gw_class = gw_node->orig_node->gwflags;
		if ( gw_node->orig_node->packet_count > max_packets ) max_packets = gw_node->orig_node->packet_count;
		if ( ( gw_node->orig_node->packet_count * gw_node->orig_node->gwflags ) > max_gw_class ) max_gw_factor = ( gw_node->orig_node->packet_count * gw_node->orig_node->gwflags );

		if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {

			tmp_curr_gw = gw_node;

			if (debug_level >= 0) {
				addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
				output( "Preferred gateway found: %s (%i,%i,%i)\n", orig_str, gw_node->orig_node->gwflags, gw_node->orig_node->packet_count, ( gw_node->orig_node->packet_count * gw_node->orig_node->gwflags ) );
			}

			break;

		}

	}


	if ( curr_gateway != tmp_curr_gw ) {

		if ( curr_gateway != NULL ) {

			if (debug_level >= 0) output( "Removing default route - better gateway found\n" );

			/* TODO remove default route */

		}

		if (debug_level >= 0) {
			addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
			output( "Adding default route to %s (%i,%i,%i)\n", orig_str, max_gw_class, max_packets, max_gw_factor );
		}

		/* TODO add default route */
		curr_gateway = tmp_curr_gw;

	}

}



static void update_routes( struct orig_node *orig_node )
{

	struct list_head *neigh_pos, *pack_pos;
	struct neigh_node *neigh_node, *next_hop;
	struct pack_node *pack_node;
	struct batman_if *max_if;
	int max_pack, max_ttl, neigh_ttl[found_ifs], neigh_pkts[found_ifs];
	static char orig_str[ADDR_STR_LEN], next_str[ADDR_STR_LEN];

	if (debug_level >= 2)
		output("update_routes() \n");

	max_ttl  = 0;
	max_pack = 0;
	next_hop = NULL;

	/* for every neighbour... */
	list_for_each(neigh_pos, &orig_node->neigh_list) {
		neigh_node = list_entry(neigh_pos, struct neigh_node, list);

		memset(neigh_pkts, 0, sizeof(neigh_pkts));
		memset(neigh_ttl, 0, sizeof(neigh_ttl));

		max_if = (struct batman_if *)if_list.next; /* first batman interface */

		list_for_each(pack_pos, &neigh_node->pack_list) {
			pack_node = list_entry(pack_pos, struct pack_node, list);
			if (pack_node->ttl > neigh_ttl[pack_node->if_incoming->if_num])
				neigh_ttl[pack_node->if_incoming->if_num] = pack_node->ttl;

			neigh_pkts[pack_node->if_incoming->if_num]++;
			if ( neigh_pkts[pack_node->if_incoming->if_num] > neigh_pkts[max_if->if_num] ) max_if = pack_node->if_incoming;
		}

		/* if received most orig_packets via this neighbour (or ) then
			select this neighbour as next hop for this origin */
		if ((neigh_pkts[max_if->if_num] > max_pack) || ((neigh_pkts[max_if->if_num] == max_pack) && (neigh_ttl[max_if->if_num] > max_ttl))) {
			max_pack = neigh_pkts[max_if->if_num];
			max_ttl = neigh_ttl[max_if->if_num];

			next_hop = neigh_node;
			if (debug_level >= 2)
				output("%d living received packets via selected router \n", neigh_pkts[max_if->if_num] );
		}
	}

	if (next_hop != NULL) {
		if (debug_level >= 2) {
			addr_to_string(orig_node->orig, orig_str, ADDR_STR_LEN);
			addr_to_string(next_hop->addr, next_str, ADDR_STR_LEN);
			output("Route to %s via %s\n", orig_str, next_str);
		}

		orig_node->packet_count = neigh_pkts[max_if->if_num];

		if (orig_node->router != next_hop->addr) {
			if (debug_level >= 2)
			output("Route changed\n");

			if (orig_node->router != 0) {
				if (debug_level >= 2)
					output("Deleting previous route\n");

				add_del_route(orig_node->orig, orig_node->router, 1, orig_node->batman_if->dev, orig_node->batman_if->udp_send_sock);
			}

			if (debug_level >= 2) { output("Adding new route\n");  }


			/* TODO: maybe the order delete, add should be changed ???? */
			orig_node->batman_if = max_if;
			add_del_route(orig_node->orig, next_hop->addr, 0, orig_node->batman_if->dev, orig_node->batman_if->udp_send_sock);

			orig_node->router = next_hop->addr;
		}
	}

}

static void update_gw_list( struct orig_node *orig_node, unsigned char new_gwflags )
{

	struct list_head *pos;
	struct gw_node *gw_node;
	static char orig_str[ADDR_STR_LEN];

	list_for_each(pos, &gw_list) {

		gw_node = list_entry(pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			if (debug_level >= 0) {

				addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
				output( "Gateway class of originator %s changed from %i to %i\n", orig_str, gw_node->orig_node->gwflags, new_gwflags );

			}

			gw_node->orig_node->gwflags = new_gwflags;
			return;

		}

	}

	if (debug_level >= 0) {
		addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
		output( "Found new gateway %s with class %i\n", orig_str, new_gwflags );
	}

	gw_node = alloc_memory(sizeof(struct gw_node));
	memset(gw_node, 0, sizeof(struct gw_node));
	INIT_LIST_HEAD(&gw_node->list);

	gw_node->orig_node = orig_node;

	list_add_tail(&gw_node->list, &gw_list);

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

	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

		if ( orig == orig_node->orig ) {

			list_for_each(neigh_pos, &orig_node->neigh_list) {
				neigh_node = list_entry(neigh_pos, struct neigh_node, list);

				list_for_each(pack_pos, &neigh_node->pack_list) {
					pack_node = list_entry(pack_pos, struct pack_node, list);

					if (orig_node->orig == orig && pack_node->seqno == seqno){
	/* 					if (debug_level >= 2)  {  output("isDuplicate(): YES \n");  } */
						return 1;
					}

				}

			}

		}

	}

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
	struct list_head *if_pos;
	struct batman_if *batman_if;
	int is_my_addr = 0, is_my_orig = 0;

	if (debug_level >= 3) {
		output("update_last_hop(): Searching originator entry of last-hop neighbour of received packet \n"); }
	orig_neigh_node = get_orig_node( neigh );
	orig_neigh_node->last_aware = get_time();


	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);

		if ( neigh == batman_if->addr.sin_addr.s_addr ) is_my_addr = 1;
		if ( in->orig == batman_if->addr.sin_addr.s_addr ) is_my_orig = 1;
	}

	if (is_my_addr != 1 && is_my_orig == 1 && in->ttl == TTL-1)	{
		if (debug_level >= 2)	{
			output("received my own packet from neighbour indicating bidirectional link, updating last_reply stamp \n");
		}
		orig_neigh_node->last_reply = get_time();
	}

	return orig_neigh_node;

}

void update_originator(struct packet *in, unsigned int neigh, struct batman_if *if_incoming)
{
	struct list_head *neigh_pos, *pack_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node = NULL;
	struct pack_node *pack_node = NULL;

	if (debug_level >= 3)
		output("update_originator(): Searching and updating originator entry of received packet,  \n");

	orig_node = get_orig_node( in->orig );

	orig_node->last_seen = get_time();
	orig_node->interval = in->interval;
	orig_node->flags = in->flags;

	if ( orig_node->gwflags != in->gwflags )
		update_gw_list( orig_node, in->gwflags );

	orig_node->gwflags = in->gwflags;

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
		pack_node->if_incoming = if_incoming;
		list_add_tail(&pack_node->list, &neigh_node->pack_list);
	} else
		output("ERROR - Updating existing packet\n");

	pack_node->ttl = in->ttl;
	pack_node->time = get_time();

	update_routes( orig_node );

}

void schedule_forward_packet( struct packet *in, int unidirectional,  struct orig_node *orig_node, unsigned int neigh )
{
	struct forw_node *forw_node, *forw_node_new;
	struct list_head *forw_pos;

	if (debug_level >= 2)
		output("schedule_forward_packet():  \n");

	if (in->ttl <= 1) {
		if (debug_level >= 2)
			output("ttl exceeded \n");
	} else if ( ( orig_node->router != neigh ) && ( orig_node->router != 0 ) ) {
		if (debug_level >= 2)
			output("not my best neighbour\n");
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

		forw_node_new->when = get_time();

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
	struct list_head *forw_pos, *if_pos, *temp;
	struct batman_if *batman_if;
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

			list_for_each(if_pos, &if_list) {

				batman_if = list_entry(if_pos, struct batman_if, list);

				if (send_packet((unsigned char *)pack, sizeof (struct packet), &batman_if->broad, batman_if->udp_send_sock) < 0) {
					output("ERROR: send_packet returned -1 \n");
					exit( -1);
				}

			}

			list_del(forw_pos);
			free_memory(forw_node);
		}
	}
}

void schedule_own_packet() {
	int queue_own = 1;
	struct forw_node *forw_node = NULL, *forw_node_new;
	struct list_head *forw_pos, *if_pos;
	struct batman_if *batman_if;

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

		list_for_each(if_pos, &if_list) {

			batman_if = list_entry(if_pos, struct batman_if, list);

			forw_node_new = alloc_memory(sizeof (struct forw_node));
			INIT_LIST_HEAD(&forw_node_new->list);

			memcpy(&forw_node_new->pack, &batman_if->out, sizeof (struct packet));
			forw_node_new->when = next_own;

			list_add(&forw_node_new->list, (forw_node == NULL ? &forw_list : forw_pos));

			next_own += orginator_interval;
			batman_if->out.seqno++;

		}

	}

}

void purge()
{
	struct list_head *orig_pos, *neigh_pos, *pack_pos, *gw_pos, *orig_temp, *neigh_temp, *pack_temp;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct pack_node *pack_node;
	struct gw_node *gw_node;
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
				} else {

					/* if this packet is not outdated the following packets won't be either */
					break;

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

			list_for_each(gw_pos, &gw_list) {

				gw_node = list_entry(gw_pos, struct gw_node, list);

				if ( gw_node->orig_node == orig_node ) {

					addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
					if (debug_level >= 0) output( "Removing gateway %s from gateway list\n", orig_str );

					list_del(gw_pos);
					free_memory(gw_pos);

					break;

				}

			}

			list_del(orig_pos);

			if ( orig_node->router != 0 ) {

				if (debug_level >= 2)
					output("Deleting route to originator \n");

				add_del_route(orig_node->orig, 0, 1, orig_node->batman_if->dev, orig_node->batman_if->udp_send_sock);
				free_memory(orig_node);

			}
		}
	}

	/* is not needed - calculate new route with next packet
	update_routes(); */
}

void send_vis_packet()
{
	struct list_head *pos;
	struct orig_node *orig_node;
	unsigned char *packet=NULL;

	int step = 5, size=0,cnt=0;

	list_for_each(pos, &orig_list) {
		orig_node = list_entry(pos, struct orig_node, list);
		if(orig_node->orig == orig_node->router)
		{
			if(cnt >= size)
			{
				size += step;
				packet = realloc_memory(packet, size * sizeof(unsigned char));
			}
			memmove(&packet[cnt], (unsigned char*)&orig_node->orig,4);
			 *(packet + cnt + 4) = (unsigned char) orig_node->packet_count;
			cnt += step;
		}
	}
	if(packet != NULL)
	{
		send_packet(packet, size * sizeof(unsigned char), &vis_if.addr, vis_if.sock);
	 	free_memory(packet);
	}
}

int batman()
{
	struct list_head *forw_pos, *orig_pos, *if_pos;
	struct forw_node *forw_node;
	struct orig_node *orig_node, *orig_neigh_node;
	struct batman_if *batman_if, *if_incoming;
	struct packet in;
	int res;
	unsigned int neigh;
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
	int forward_old;
	int is_my_addr, is_my_orig, is_broadcast, is_duplicate;
	int time_count = 0;

	next_own = 0;

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);

		batman_if->out.orig = batman_if->addr.sin_addr.s_addr;
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = TTL;
		batman_if->out.seqno = 0;
		batman_if->out.interval = orginator_interval;
		batman_if->out.gwflags = gateway_class;
		batman_if->out.version = BATMAN_VERSION;
	}

	forward_old = get_forwarding();
	set_forwarding(1);

	while (!is_aborted())
	{
		if (debug_level >= 2)
			output(" \n \n");

		schedule_own_packet();
		if(vis_if.sock && time_count == 50)
		{
			time_count = 0;
			send_vis_packet();
		}

		list_for_each(forw_pos, &forw_list) {
			forw_node = list_entry(forw_pos, struct forw_node, list);
			res = receive_packet((unsigned char *)&in, sizeof (struct packet), &neigh, forw_node->when, &if_incoming);
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

			is_my_addr = is_my_orig = is_broadcast = is_duplicate = 0;

			list_for_each(if_pos, &if_list) {
				batman_if = list_entry(if_pos, struct batman_if, list);

				if ( neigh == batman_if->addr.sin_addr.s_addr ) is_my_addr = 1;
				if ( in.orig == batman_if->addr.sin_addr.s_addr ) is_my_orig = 1;
				if ( neigh == batman_if->broad.sin_addr.s_addr ) is_broadcast = 1;
			}

			is_duplicate = isDuplicate( in.orig, in.seqno );

			if (is_my_addr == 1 /* && in.orig == my_addr */) {

				if (debug_level >= 3) {
					addr_to_string(neigh, neigh_str, sizeof (neigh_str));
					output("Ignoring all (zero-hop) packets send by me (sender: %s)\n", neigh_str);
				}

			} else if (is_broadcast == 1) {

				if (debug_level >= 0) {
					addr_to_string(neigh, neigh_str, sizeof (neigh));
					output("Ignoring all packets with broadcast source IP (sender: %s)\n", neigh_str);
				}

			} else {

				orig_neigh_node = update_last_hop( &in, neigh );

				if (debug_level >= 2) {
					if ( is_duplicate )
						output("Duplicate packet \n");

					if ( in.orig == neigh )
						output("Originator packet from neighbour \n");

					if ( is_my_orig == 1 )
						output("Originator packet from myself (via neighbour) \n");

					if ( in.flags & UNIDIRECTIONAL )
						output("Packet with unidirectional flag \n");

					if ( isBidirectionalNeigh( orig_neigh_node ) )
						output("received via bidirectional link \n");

					if ( in.gwflags != 0 )
						output("Is an internet gateway (class %i) \n", in.gwflags);
				}


				if ( in.version != BATMAN_VERSION ) {

					if (debug_level >= 1)
						output( "Incompatible batman version (%i) - ignoring packet... \n", in.version );

				} else if ( in.orig == neigh && in.ttl == TTL &&
						!isBidirectionalNeigh( orig_neigh_node )  &&
						!is_duplicate &&
						!(in.flags & UNIDIRECTIONAL) ) {

					schedule_forward_packet(&in, 1, orig_neigh_node, neigh);

				} else if ( in.orig == neigh && in.ttl == TTL &&
						isBidirectionalNeigh( orig_neigh_node ) &&
						!is_duplicate &&
						!(in.flags & UNIDIRECTIONAL) ) {

					update_originator( &in, neigh, if_incoming );
					schedule_forward_packet(&in, 1, orig_neigh_node, neigh);

				} else if ( in.orig != neigh && is_my_orig != 1 &&
						isBidirectionalNeigh( orig_neigh_node ) &&
						!is_duplicate &&
						!(in.flags & UNIDIRECTIONAL) ) {

					update_originator( &in, neigh, if_incoming );
					schedule_forward_packet(&in, 1, orig_neigh_node, neigh);

				} else {
					if (debug_level >= 3)
						output("Ignoring packet... \n");
				}
			}
		}

		send_outstanding_packets();

		purge();
		debug();
		time_count++;
	}

	output("Deleting all BATMAN routes\n");

	list_for_each(orig_pos, &orig_list) {
		orig_node = list_entry(orig_pos, struct orig_node, list);

		if (orig_node->router != 0)
			add_del_route(orig_node->orig, orig_node->router, 1, orig_node->batman_if->dev, batman_if->udp_send_sock);
	}

	set_forwarding(forward_old);

	return 0;
}
