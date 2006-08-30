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
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <err.h>
#include <limits.h>

/* Resolve namespace pollution from sys/queue.h */
#ifdef LIST_HEAD
#undef LIST_HEAD
#endif

#include "os.h"
#include "batman.h"
#include "list.h"

static struct timeval start_time;
static int stop;

/* Message structure used to interface the kernel routing table.
 * See route(4) for details on the message passing interface for
 * manipulating the kernel routing table in FreeBSD.
 * We transmit at most two addresses at once: a destination host
 * and a gateway.
 */
struct rt_msg
{
	struct rt_msghdr hdr;
	struct sockaddr_in dest;
	struct sockaddr_in gateway;
};

#define SYSCTL_FORWARDING "net.inet.ip.forwarding"

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
	/* FreeBSD allows us to set the boolean IP forwarding
	 * sysctl to anything. Check the value for sanity. */
	if (state < 0 || state > 1)
	{
		errno = EINVAL;
		err(1, "set_forwarding: %i", state);
	}

	if (sysctlbyname(SYSCTL_FORWARDING, NULL, NULL, &state, sizeof(state)) == -1)
	{
		err(1, "Cannot enable packet forwarding");
	}
}

int get_forwarding(void)
{
	int state;
	size_t len;
	
	len = sizeof(state);
	if (sysctlbyname(SYSCTL_FORWARDING, &state, &len, NULL, 0) == -1)
	{
		err(1, "Cannot tell if packet forwarding is enabled");
	}
	return state;
}

void close_all_sockets()
{
	struct list_head *if_pos;
	struct batman_if *batman_if;

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);
		close(batman_if->udp_send_sock);
		close(batman_if->udp_recv_sock);
	}
}

void add_del_route(unsigned int dest, unsigned int router, int del,
		char *dev, int sock)
{
	char str1[16], str2[16];
	int rt_sock;
	static unsigned int seq = 0;
	struct rt_msg msg;
	struct sockaddr_in *so_dest, *so_gateway;
	struct sockaddr_in ifname;
	socklen_t ifname_len;
	ssize_t len;
	pid_t pid;

	so_dest = NULL;
	so_gateway = NULL;

	memset(&msg, 0, sizeof(struct rt_msg));

	inet_ntop(AF_INET, &dest, str1, sizeof (str1));
	inet_ntop(AF_INET, &router, str2, sizeof (str2));

	msg.hdr.rtm_type = del ? RTM_DELETE : RTM_ADD;
	msg.hdr.rtm_version = RTM_VERSION;
	msg.hdr.rtm_flags = RTF_STATIC | RTF_UP | RTF_HOST;
	msg.hdr.rtm_addrs = RTA_DST;

	so_dest = &msg.dest;
	so_dest->sin_family = AF_INET;
	so_dest->sin_len = sizeof(struct sockaddr_in);
	so_dest->sin_addr.s_addr = dest;

	msg.hdr.rtm_msglen = sizeof(struct rt_msghdr)
		+ (2 * sizeof(struct sockaddr_in));

	msg.hdr.rtm_flags |= RTF_GATEWAY;
	msg.hdr.rtm_addrs |= RTA_GATEWAY;

	so_gateway = &msg.gateway;
	so_gateway->sin_family = AF_INET;
	so_gateway->sin_len = sizeof(struct sockaddr_in);

	if (dest != router) {
		/* This is not a direct route; router is our gateway
		 * to the remote host.
		 * We essentially run 'route add <remote ip> <gateway ip> */
		so_gateway->sin_addr.s_addr = router;
	} else {
		/* This is a direct route to the remote host.
		 * We use our own IP address as gateway.
		 * We essentially run 'route add <remote ip> <local ip> */
		ifname_len = sizeof(struct sockaddr_in);
		if (getsockname(sock, (struct sockaddr*)&ifname, &ifname_len) == -1) {
			err(1, "Could not get name of interface %s", dev);
		}
		so_gateway->sin_addr.s_addr = ifname.sin_addr.s_addr;
	}

	output("%s route to %s via %s\n", del ? "Deleting" : "Adding", str1, str2);

	rt_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (rt_sock < 0)
		err(1, "Could not open socket to routing table");

	pid = getpid();
	len = 0;
	seq++;

	/* Send message */
	do {
		msg.hdr.rtm_seq = seq;
		len = write(rt_sock, &msg, msg.hdr.rtm_msglen);
		if (len < 0)
		{
			warn("Error sending routing message to kernel");
			err(1, "Cannot %s route to %s",
				del ? "delete" : "add", str1);
		}
	} while (len < msg.hdr.rtm_msglen);

	/* Get reply */
	do {
		len = read(rt_sock, &msg, sizeof(struct rt_msg));
		if (len < 0)
			err(1, "Error reading from routing socket");
	} while (len > 0 && (msg.hdr.rtm_seq != seq || msg.hdr.rtm_pid != pid));

	/* Evaluate reply */
	if (msg.hdr.rtm_version != RTM_VERSION)
	{
		warn("routing message version mismatch: "
		    "compiled with version %i, "
		    "but running kernel uses version %i", RTM_VERSION,
		    msg.hdr.rtm_version);
	}
	if (msg.hdr.rtm_errno)
	{
		errno = msg.hdr.rtm_errno;
		err(1, "Cannot %s route to %s",
			del ? "delete" : "add", str1);
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

void *realloc_memory(void *ptr, int len)
{
	void *res = realloc(ptr,len);

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

int receive_packet(unsigned char *buff, int len, unsigned int *neigh, unsigned int timeout, struct batman_if **if_incoming)
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

		FD_SET(batman_if->udp_recv_sock, &wait_set);
		if ( batman_if->udp_recv_sock > max_sock ) max_sock = batman_if->udp_recv_sock;

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

		if ( FD_ISSET( batman_if->udp_recv_sock, &wait_set) ) {

			if (recvfrom(batman_if->udp_recv_sock, buff, len, 0, (struct sockaddr *)&addr, &addr_len) < 0)
			{
				fprintf(stderr, "Cannot receive packet: %s\n", strerror(errno));
				return -1;
			}

			(*if_incoming) = batman_if;
			break;

		}

	}


	*neigh = addr.sin_addr.s_addr;

	return 1;
}

int send_packet(unsigned char *buff, int len, struct sockaddr_in *broad, int sock)
{
//#define STSP_DEBUG
#ifdef STSP_DEBUG
	struct ifreq int_req;
	char str[16];

	memset(&int_req, 0, sizeof (struct ifreq));
	strcpy(int_req.ifr_name, "wi0");

	if (ioctl(sock, SIOCGIFADDR, &int_req) < 0)
	{
		fprintf(stderr, "Cannot get IP address of interface %s\n", "wi0");
		close_all_sockets();
		exit(EXIT_FAILURE);
	}

	addr_to_string(((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr, str, sizeof (str));
	printf("Sending packet with source IP %s\n", str);
#endif
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

	while ( ( optchar = getopt ( argc, argv, "d:hHo:g:p:r:s:" ) ) != -1 ) {

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

			case 's':

				errno = 0;
				if ( inet_pton(AF_INET, optarg, &tmp_pref_gw) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_pref_gw.s_addr;


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

		batman_if->udp_send_sock = socket(PF_INET, SOCK_DGRAM, 0);
		if (batman_if->udp_send_sock < 0)
		{
			fprintf(stderr, "Cannot create send socket: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		batman_if->udp_recv_sock = socket(PF_INET, SOCK_DGRAM, 0);
		if (batman_if->udp_recv_sock < 0)
		{
			fprintf(stderr, "Cannot create receive socket: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		memset(&int_req, 0, sizeof (struct ifreq));
		strcpy(int_req.ifr_name, batman_if->dev);

		if (ioctl(batman_if->udp_recv_sock, SIOCGIFADDR, &int_req) < 0)
		{
			fprintf(stderr, "Cannot get IP address of interface %s\n", batman_if->dev);
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		batman_if->addr.sin_family = AF_INET;
		batman_if->addr.sin_port = htons(PORT);
		batman_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		if (ioctl(batman_if->udp_recv_sock, SIOCGIFBRDADDR, &int_req) < 0)
		{
			fprintf(stderr, "Cannot get broadcast IP address of interface %s\n", batman_if->dev);
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		batman_if->broad.sin_family = AF_INET;
		batman_if->broad.sin_port = htons(PORT);
		batman_if->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

		if (setsockopt(batman_if->udp_send_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof (int)) < 0)
		{
			fprintf(stderr, "Cannot enable broadcasts: %s\n", strerror(errno));
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		if (bind(batman_if->udp_send_sock, (struct sockaddr *)&batman_if->addr, sizeof (struct sockaddr_in)) < 0)
		{
			fprintf(stderr, "Cannot bind send socket: %s\n", strerror(errno));
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		if (bind(batman_if->udp_recv_sock, (struct sockaddr *)&batman_if->broad, sizeof (struct sockaddr_in)) < 0)
		{
			fprintf(stderr, "Cannot bind receive socket: %s\n", strerror(errno));
			close_all_sockets();
			exit(EXIT_FAILURE);
		}

		addr_to_string(batman_if->addr.sin_addr.s_addr, str1, sizeof (str1));
		addr_to_string(batman_if->broad.sin_addr.s_addr, str2, sizeof (str2));

		printf("Using interface %s with address %s and broadcast address %s\n", batman_if->dev, str1, str2);

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
	if ( ( debug_level > 0 ) && ( orginator_interval != 1000 ) ) printf( "orginator interval: %i\n", orginator_interval );
	if ( ( debug_level > 0 ) && ( gateway_class > 0 ) ) printf( "gateway class: %i\n", gateway_class );
	if ( ( debug_level > 0 ) && ( routing_class > 0 ) ) printf( "routing class: %i\n", routing_class );
	if ( ( debug_level > 0 ) && ( pref_gateway > 0 ) ) {
		addr_to_string(pref_gateway, str1, sizeof (str1));
		printf( "preferred gateway: %s\n", str1 );
	}


	stop = 0;

	signal(SIGINT, handler);

	gettimeofday(&start_time, NULL);

	srand(getpid());

	res = batman();

	close_all_sockets();
	return res;
}
