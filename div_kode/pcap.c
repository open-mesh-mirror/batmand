#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if ( handle == NULL ) {
		fprintf ( stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
















	return(0);
}
