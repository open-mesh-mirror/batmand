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

#define VERSION "0.1"
#define BATMAN_VERSION 1
#define PORT 1966

/*
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with: */

// #define INTERVAL 1000 /* orginator message interval in miliseconds */
#define BIDIRECT_TO 3000 /* bidirectional neighbour reply timeout in ms */
#define JITTER 100 /* jitter to reduce broadcast collisions in ms */
#define TTL 50 /* Time To Live of broadcast messages */
#define TIMEOUT 30000 /* sliding window size of received orginator messages in ms */




struct packet;
struct orig_node; /* structure for orig_list maintaining nodes of mesh */
struct neigh_node;
struct pack_node;
struct forw_node; /* structure for forw_list maintaining packets to be send/forwarded */

/*
static void update_routes();
static void debug();
*/


int batman(unsigned int addr);

#endif
