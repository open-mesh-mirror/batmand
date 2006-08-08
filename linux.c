/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/if.h>

#include "os.h"
#include "batman.h"
#include "list.h"

static struct timeval start_time;
static int stop;


static void get_time_internal(struct timeval *tv)
{
	int sec;
	int usec;
	gettimeofday(tv, NULL);

	sec = tv->tv_sec - start_time.tv_sec;
	usec = tv->tv_usec - start_time.tv_usec;

	if (usec < 0)
	{
		sec--;
		usec += 1000000;
	}

	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

unsigned int get_time(void)
{
	struct timeval tv;

	get_time_internal(&tv);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void output(char *format, ...)
{
	va_list args;

	printf("[%10u] ", get_time());

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void set_forwarding(int state)
{
	FILE *f;

	if((f = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL)
		return;

	fprintf(f, "%d", state);
	fclose(f);
}

int get_forwarding(void)
{
	FILE *f;
	int state = 0;

	if((f = fopen("/proc/sys/net/ipv4/ip_forward", "r")) == NULL)
		return 0;

	fscanf(f, "%d", &state);
	fclose(f);

	return state;
}

void close_all_sockets()
{
	struct list_head *if_pos;
	struct batman_if *batman_if;

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);
		close(batman_if->sock);
	}
}

void add_del_route(unsigned int dest, unsigned int router, int del, char *dev, int sock)
{
	struct rtentry route;
	char str1[16], str2[16];
	struct sockaddr_in *addr;

	inet_ntop(AF_INET, &dest, str1, sizeof (str1));
	inet_ntop(AF_INET, &router, str2, sizeof (str2));

	output("%s route to %s via %s\n", del ? "Deleting" : "Adding", str1, str2);

	memset(&route, 0, sizeof (struct rtentry));

	addr = (struct sockaddr_in *)&route.rt_dst;

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = dest;

	addr = (struct sockaddr_in *)&route.rt_genmask;

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0xffffffff;

	route.rt_flags = RTF_HOST | RTF_UP;

	if (dest != router)
	{
		addr = (struct sockaddr_in *)&route.rt_gateway;

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = router;

		route.rt_flags |= RTF_GATEWAY;
	}

	route.rt_metric = 1;

	route.rt_dev = dev;

	if (ioctl(sock, del ? SIOCDELRT : SIOCADDRT, &route) < 0)
	{
		fprintf(stderr, "Cannot %s route to %s via %s: %s\n",
			del ? "delete" : "add", str1, str2, strerror(errno));
	}
}

int is_aborted()
{
	return stop != 0;
}

void *alloc_memory(int len)
{
	void *res = malloc(len);

	if (res == NULL)
	{
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	return res;
}

void free_memory(void *mem)
{
	free(mem);
}

void addr_to_string(unsigned int addr, char *str, int len)
{
	inet_ntop(AF_INET, &addr, str, len);
}

int rand_num(int limit)
{
	return rand() % limit;
}

int receive_packet(unsigned char *buff, int len, unsigned int *neigh, unsigned int timeout, void *if_incoming)
{
	fd_set wait_set;
	int res, max_sock = 0;
	struct sockaddr_in addr;
	unsigned int addr_len;
	struct timeval tv;
	struct list_head *if_pos;
	struct batman_if *batman_if;

	int diff = timeout - get_time();

	if (diff < 0)
		return 0;

	tv.tv_sec = diff / 1000;
	tv.tv_usec = (diff % 1000) * 1000;

	FD_ZERO(&wait_set);

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);

		FD_SET(batman_if->sock, &wait_set);
		if ( batman_if->sock > max_sock ) max_sock = batman_if->sock;
	}

	for (;;)
	{
		res = select(max_sock + 1, &wait_set, NULL, NULL, &tv);

		if (res >= 0)
			break;

		if (errno != EINTR)
		{
			fprintf(stderr, "Cannot select: %s\n", strerror(errno));
			return -1;
		}
	}

	if (res == 0)
		return 0;

	addr_len = sizeof (struct sockaddr_in);

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);

		if ( FD_ISSET( batman_if->sock, &wait_set) ) {

			if (recvfrom(batman_if->sock, buff, len, 0, (struct sockaddr *)&addr, &addr_len) < 0)
			{
				fprintf(stderr, "Cannot receive packet: %s\n", strerror(errno));
				return -1;
			}

			if_incoming = batman_if;

			break;

		}

	}


	*neigh = addr.sin_addr.s_addr;

	return 1;
}

int send_packet(unsigned char *buff, int len, struct sockaddr_in *broad, int sock)
{
	if (sendto(sock, buff, len, 0, (struct sockaddr *)broad, sizeof (struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "Cannot send packet: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void handler(int sig)
{
	stop = 1;
}

static void usage(void)
{
	fprintf(stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf(stderr, "       -d debug level\n" );
	fprintf(stderr, "       -g gateway class\n" );
	fprintf(stderr, "       -h this help\n" );
	fprintf(stderr, "       -H verbose help\n" );
	fprintf(stderr, "       -o orginator interval in ms\n" );
	fprintf(stderr, "       -p preferred gateway\n" );
	fprintf(stderr, "       -r routing class\n" );
}

static void verbose_usage(void)
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

}

int main(int argc, char *argv[])
{
	struct in_addr tmp_pref_gw;
	struct batman_if *batman_if;
	struct ifreq int_req;
	int on = 1, res, optchar, found_args = 1;
	char str1[16], str2[16], *dev;

	dev = NULL;
	memset(&tmp_pref_gw, 0, sizeof (struct in_addr));

	printf( "B.A.T.M.A.N-II v%s (internal version %i)\n", VERSION, BATMAN_VERSION );

	while ( ( optchar = getopt ( argc, argv, "d:hHo:g:r:p:" ) ) != -1 ) {

		switch ( optchar ) {

			case 'd':

				errno = 0;
				debug_level = strtol (optarg, NULL , 10);

				if ( (errno == ERANGE && (debug_level == LONG_MAX || debug_level == LONG_MIN) ) || (errno != 0 && debug_level == 0) ) {
						perror("strtol");
						exit(EXIT_FAILURE);
				}

				if ( debug_level < 0 || debug_level > 3 ) {
						printf( "Invalid debug level: %i\nDebug level has to be between 0 and 3.\n", debug_level );
						exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'g':

				errno = 0;
				gateway_class = strtol (optarg, NULL , 10);

				if ( (errno == ERANGE && (gateway_class == LONG_MAX || gateway_class == LONG_MIN) ) || (errno != 0 && gateway_class == 0) ) {
					perror("strtol");
					exit(EXIT_FAILURE);
				}

				if ( gateway_class < 0 || gateway_class > 32 ) {
					printf( "Invalid gateway class specified: %i.\nThe class is a value between 0 and 32.\n", gateway_class );
					exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'H':
				verbose_usage();
				return (0);

			case 'o':

				errno = 0;
				orginator_interval = strtol (optarg, NULL , 10);

				if ( (errno == ERANGE && (orginator_interval == LONG_MAX || orginator_interval == LONG_MIN) ) || (errno != 0 && orginator_interval == 0) ) {
					perror("strtol");
					exit(EXIT_FAILURE);
				}

				if (orginator_interval < 1) {
					printf( "Invalid orginator interval specified: %i.\nThe Interval has to be greater than 0.\n", orginator_interval );
					exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'p':

				errno = 0;
				if ( inet_pton(AF_INET, optarg, &tmp_pref_gw) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_pref_gw.s_addr;

				found_args += 2;
				break;

			case 'r':

				errno = 0;
				routing_class = strtol (optarg, NULL , 10);

				if ( (errno == ERANGE && (routing_class == LONG_MAX || routing_class == LONG_MIN) ) || (errno != 0 && routing_class == 0) ) {
					perror("strtol");
					exit(EXIT_FAILURE);
				}

				if (routing_class < 0 || routing_class > 3) {
					printf( "Invalid routing class specified: %i.\nThe class is a value between 0 and 3.\n", routing_class );
					exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'h':
			default:
				usage();
				return (0);

          }

	}


	while ( argc > found_args ) {

		batman_if = alloc_memory(sizeof(struct batman_if));
		memset(batman_if, 0, sizeof(struct batman_if));
		INIT_LIST_HEAD(&batman_if->list);

		batman_if->dev = argv[found_args];
		batman_if->if_num = found_ifs;

		list_add_tail(&batman_if->list, &if_list);

		if ( strlen(batman_if->dev) > IFNAMSIZ - 1 ) {
			fprintf(stderr, "Interface name too long: %s\n", batman_if->dev);
			exit(EXIT_FAILURE);
		}

		batman_if->sock = socket(PF_INET, SOCK_DGRAM, 0);

		if (batman_if->sock < 0)
		{
			fprintf(stderr, "Cannot create socket: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		memset(&int_req, 0, sizeof (struct ifreq));
		strcpy(int_req.ifr_name, batman_if->dev);

		if (ioctl(batman_if->sock, SIOCGIFADDR, &int_req) < 0)
		{
			fprintf(stderr, "Cannot get IP address of interface %s\n", batman_if->dev);
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		batman_if->addr.sin_family = AF_INET;
		batman_if->addr.sin_port = htons(PORT);
		batman_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		if (ioctl(batman_if->sock, SIOCGIFBRDADDR, &int_req) < 0)
		{
			fprintf(stderr, "Cannot get broadcast IP address of interface %s\n", batman_if->dev);
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		batman_if->broad.sin_family = AF_INET;
		batman_if->broad.sin_port = htons(PORT);
		batman_if->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

		if (setsockopt(batman_if->sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof (int)) < 0)
		{
			fprintf(stderr, "Cannot enable broadcasts: %s\n", strerror(errno));
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		if (bind(batman_if->sock, (struct sockaddr *)&batman_if->addr, sizeof (struct sockaddr_in)) < 0)
		{
			fprintf(stderr, "Cannot bind socket: %s\n", strerror(errno));
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		addr_to_string(batman_if->addr.sin_addr.s_addr, str1, sizeof (str1));
		addr_to_string(batman_if->broad.sin_addr.s_addr, str2, sizeof (str2));

		printf("Using address %s and broadcast address %s\n", str1, str2);

		found_ifs++;
		found_args++;

	}


	if (found_ifs == 0)
	{
	  fprintf(stderr, "Error - no interface specified\n");
		usage();
		return 1;
	}

	if ( ( gateway_class != 0 ) && ( routing_class != 0 ) )
	{
		fprintf(stderr, "Error - routing class can't be set while gateway class is in use !\n");
		usage();
		return 1;
	}

	if ( ( gateway_class != 0 ) && ( pref_gateway != 0 ) )
	{
		fprintf(stderr, "Error - preferred gateway can't be set while gateway class is in use !\n");
		usage();
		return 1;
	}

	if ( debug_level > 0 ) printf("debug level: %i\n", debug_level);
	if ( debug_level > 0 ) printf( "Using interface: %s\n", dev );
	if ( ( debug_level > 0 ) && ( orginator_interval != 1000 ) ) printf( "orginator interval: %i\n", orginator_interval );
	if ( ( debug_level > 0 ) && ( gateway_class > 0 ) ) printf( "gateway class: %i\n", gateway_class );
	if ( ( debug_level > 0 ) && ( routing_class > 0 ) ) printf( "routing class: %i\n", routing_class );
	if ( ( debug_level > 0 ) && ( pref_gateway > 0 ) ) {
		addr_to_string(pref_gateway, str1, sizeof (str1));
		printf( "preferred gateway: %s\n", str1 );
	}


	stop = 0;

	signal(SIGINT, handler);

// 	null.sin_family = AF_INET;
// 	null.sin_port = htons(PORT);
// 	null.sin_addr.s_addr = 0;
/*
	if (bind(sock, (struct sockaddr *)&null, sizeof (struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "Cannot bind socket: %s\n", strerror(errno));
		close(sock);
		return 1;
	}*/

	gettimeofday(&start_time, NULL);

	srand(getpid());

	res = batman();

	close_all_sockets();
	return res;
}
