#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm-generic/errno-base.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>

void print_usage()
{
	fprintf(stderr, "usage: [-d <device-name>] [-n <nr-packets>] [-h]\n");
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *hdr,
			  const uint8_t *bytes)
{
	struct ethhdr *eth = (struct ethhdr *) bytes;

	//printf("dest: %%02x:%02x:%02x:%02x:%02x:%02x\n", (uint8_t *) &(eth->h_dest));
	//printf("src: %6X\n", (unsigned char *) eth->h_source);
	printf(".");
}

int main (int argc, char *argv)
{
	char *errbuf;
	char *dev;
	int ret = 0;
	int n = 10;
	int c;

	while ((c = getopt(argc, (char * const *) argv, "d:n:h")) != EOF) {
		switch (c) {
			case 'd':
				dev = optarg;
				break;
			case 'n':
				n = atoi(optarg);
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
			default:
				print_usage();
				exit(EXIT_FAILURE);
		}
	}

	errbuf = (char *) malloc(PCAP_ERRBUF_SIZE);
	if (!errbuf)
		return -ENOMEM;

	pcap_t *p = pcap_create("ens2f0", errbuf);
	if (!p) {
		fprintf(stderr, "pcap_create failed, %s\n");
		goto out;
	} else {
		ret = pcap_activate(p);		
		if (ret > 0) {
			fprintf(stderr, "pcap warning: %s\n", pcap_statustostr(ret));
		} else if (ret < 0) {
			pcap_perror(p, "pcap error:");
			goto out;
		}
	}

	ret = pcap_loop(p, n, handle_packet, NULL);
	fprintf(stderr, "\npcap_loop returned: %d\n", ret);
	
out:
	pcap_close(p);
	return 0;
}


