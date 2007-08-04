/*
 * vis-types.h
 *
 * Copyright (C) 2006 Marek Lindner:
 *
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



#define DATA_TYPE_NEIGH 1
#define DATA_TYPE_SEC_IF 2
#define DATA_TYPE_HNA 3



struct vis_packet {
	unsigned int sender_ip;
	unsigned char version;
	unsigned char gw_class;
	unsigned char seq_range;
};

struct vis_data {
	unsigned char type;
	unsigned int ip;
	unsigned char data;
};

