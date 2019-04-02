#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>

#define DEBUG 0
#define debug_print(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

static int magic = 0x41414142;
static pcap_t *p;

void exitfunc(int sig)
{
	if (sig == SIGALRM)
		printf("timed out\n");
	pcap_close(p);
	_exit(1);
}

void print_usage()
{
	fprintf(stderr, "usage: [-d device_name] [-n nr_packets]"
			" [-t timeout_in_seconds] [-h]\n");
}

static void handle_packet(unsigned char *args, const struct pcap_pkthdr *hdr,
			  const unsigned char *packet_body)
{
	struct ethhdr *eth = (struct ethhdr *) packet_body;
	unsigned int *p = (unsigned int *) ((unsigned char *) (packet_body + 14));
	uint16_t eth_type = 0x0800;

	if (!eth)
		return;
	if (ntohs(eth->h_proto) != ETH_P_IP) {
		debug_print("wrong eth type value %04hX\n", eth->h_proto);
		return;
	}

	debug_print("Packet capture length: %d\n", hdr->caplen);
	debug_print("Packet total length: %d\n", hdr->len);
	debug_print("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	debug_print("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	debug_print("Payload: %02X:%02X:%02X:%02X\n",
		p[0], p[1], p[2], p[3]);
	if (ntohl(*p) == magic) {
		debug_print("magic value found %04X\n", magic);
		pcap_breakloop((pcap_t *) args);
	}
	fprintf(stderr, ".");
}

int main (int argc, char *argv)
{
	struct pcap_pkthdr packet_header;
	const uint8_t *packet;
	int timeout = 5;
	char *errbuf;
	int ret = 0;
	int n = 10;
	char *dev;
	int c;
	int i;

	while ((c = getopt(argc, (char * const *) argv, "d:n:t:h")) != EOF) {
		switch (c) {
			case 'd':
				dev = optarg;
				break;
			case 'n':
				n = atoi(optarg);
				break;
			case 't':
				timeout = atoi(optarg);
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

	p = pcap_create(dev, errbuf);
	debug_print("Listening on device %s\n", dev);
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

	signal(SIGALRM, exitfunc);
	alarm(timeout);

	ret = pcap_loop(p, n, handle_packet, (u_char *) p);

	fprintf(stderr, "\n");
	debug_print("\npcap_loop returned: %d\n", ret);

out:
	pcap_close(p);
	if (ret == PCAP_ERROR_BREAK)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}


