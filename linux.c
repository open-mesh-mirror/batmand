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

static struct timeval start_time;
static struct sockaddr_in broad;
static int sock;
static int stop;
static char *dev;
extern int debug_level;
extern int orginator_interval;
extern int gateway_class;


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

void add_del_route(unsigned int dest, unsigned int router, int del)
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

int receive_packet(unsigned char *buff, int len, unsigned int *neigh, unsigned int timeout)
{
	fd_set wait_set;
	int res;
	struct sockaddr_in addr;
	unsigned int addr_len;
	struct timeval tv;

	int diff = timeout - get_time();

	if (diff < 0)
		return 0;

	tv.tv_sec = diff / 1000;
	tv.tv_usec = (diff % 1000) * 1000;

	FD_ZERO(&wait_set);
	FD_SET(sock, &wait_set);

	for (;;)
	{
		res = select(sock + 1, &wait_set, NULL, NULL, &tv);

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

	if (recvfrom(sock, buff, len, 0, (struct sockaddr *)&addr, &addr_len) < 0)
	{
		fprintf(stderr, "Cannot receive packet: %s\n", strerror(errno));
		return -1;
	}

	*neigh = addr.sin_addr.s_addr;

	return 1;
}

int send_packet(unsigned char *buff, int len)
{
	if (sendto(sock, buff, len, 0, (struct sockaddr *)&broad, sizeof (struct sockaddr_in)) < 0)
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
	fprintf(stderr, "Usage: batman -i interface [options]\n");
	fprintf(stderr, "       -o [option] orginator interval\n");
	fprintf(stderr, "       -d [option] debug level\n");
	fprintf(stderr, "       -g [option] gateway class\n");
	fprintf(stderr, "       -h this help\n");
}

int main(int argc, char *argv[])
{
	struct sockaddr_in addr, null;
	int on;
	int res;
	int optchar;
	struct ifreq int_req;
	char str1[16], str2[16];

	printf("B.A.T.M.A.N-II %s\n", VERSION);
	dev = NULL;

	while ( ( optchar = getopt ( argc, argv, "d:ho:i:" ) ) != -1 ) {

		switch ( optchar ) {

			case 'd':
			
			errno = 0;
			debug_level = strtol (optarg, NULL , 10);
		
			if ((errno == ERANGE && (debug_level == LONG_MAX || debug_level == LONG_MIN))|| (errno != 0 && debug_level == 0)) {
					perror("strtol");
					exit(EXIT_FAILURE);
			} 
			
			if (debug_level < 0 || debug_level > 3){
					printf( "Invalid debug level: %i\n Debug level has to be between 0 and 3.\n", debug_level );
					exit(EXIT_FAILURE);
			}

			printf(" debug level: %i\n", debug_level);
			break;

			case 'o':
			
				errno = 0;
				orginator_interval = strtol (optarg, NULL , 10);
			
				if ((errno == ERANGE && (orginator_interval == LONG_MAX || orginator_interval == LONG_MIN))	|| (errno != 0 && orginator_interval == 0)) {
						perror("strtol");
						exit(EXIT_FAILURE);
				} 
				
				if (orginator_interval < 1){
						printf( "Invalid orginator interval specified: %i. The Interval has to be greater than 0.\n", orginator_interval );
						exit(EXIT_FAILURE);
				}

				
				printf( "interval: %i\n", orginator_interval );
				break;
								
			case 'g':
			
				errno = 0;
				gateway_class = strtol (optarg, NULL , 10);
					
				if ((errno == ERANGE && (gateway_class == LONG_MAX || gateway_class == LONG_MIN))
								|| (errno != 0 && gateway_class == 0)) {
						perror("strtol");
						exit(EXIT_FAILURE);
				} 
				
				if (gateway_class < 0 || gateway_class > 32){
						printf( "Invalid orginator interval specified: %i. The Interval has to be between 0 and 32.\n", gateway_class );
						exit(EXIT_FAILURE);
				}

				
				printf( "interval: %i\n", gateway_class );
				break;
					
			case 'i':
				dev = optarg;
					if (strlen(dev) > IFNAMSIZ - 1)
					{
						fprintf(stderr, "Interface name too long\n");
						exit(EXIT_FAILURE);
					}
				printf(" interface:%s", dev);
				break;

			case 'h':
			default:
					usage();
					return (0);

          }

	}
	
	if (dev == NULL)
	{
	  fprintf(stderr, "Error - no interface specified\n");
		usage();
		return 1;
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (sock < 0)
	{
		fprintf(stderr, "Cannot create socket: %s", strerror(errno));
		return 1;
	}

	memset(&int_req, 0, sizeof (struct ifreq));
	strcpy(int_req.ifr_name, dev);

	if (ioctl(sock, SIOCGIFADDR, &int_req) < 0)
	{
		fprintf(stderr, "Cannot get IP address of interface %s\n", argv[1]);
		close(sock);
		return 1;
	}

	addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	if (ioctl(sock, SIOCGIFBRDADDR, &int_req) < 0)
	{
		fprintf(stderr, "Cannot get broadcast IP address of interface %s\n", argv[1]);
		close(sock);
		return 1;
	}

	broad.sin_family = AF_INET;
	broad.sin_port = htons(PORT);
	broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

	addr_to_string(addr.sin_addr.s_addr, str1, sizeof (str1));
	addr_to_string(broad.sin_addr.s_addr, str2, sizeof (str2));

	printf("Using address %s and broadcast address %s\n", str1, str2);

	stop = 0;

	signal(SIGINT, handler);

	on = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof (int)) < 0)
	{
		fprintf(stderr, "Cannot enable broadcasts: %s\n", strerror(errno));
		close(sock);
		return 1;
	}

	null.sin_family = AF_INET;
	null.sin_port = htons(PORT);
	null.sin_addr.s_addr = 0;

	if (bind(sock, (struct sockaddr *)&null, sizeof (struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "Cannot bind socket: %s\n", strerror(errno));
		close(sock);
		return 1;
	}

	gettimeofday(&start_time, NULL);

	srand(getpid());

	res = batman(addr.sin_addr.s_addr);

	close(sock);
	return res;
}
