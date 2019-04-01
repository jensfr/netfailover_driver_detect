#include <stdlib.h>
#include <stdio.h>
#include <asm-generic/errno-base.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>

static void handle_packet(u_char *user, const struct pcap_pkthdr *hdr,
			  const uint8_t *bytes)
{
	struct ethhdr *eth = (struct ethhdr *) bytes;

	//printf("dest: %%02x:%02x:%02x:%02x:%02x:%02x\n", (uint8_t *) &(eth->h_dest));
	//printf("src: %6X\n", (unsigned char *) eth->h_source);
	printf(".");
}

int main (void)
{
	char *errbuf;
	int ret = 0;

	errbuf = (char *) malloc(PCAP_ERRBUF_SIZE);
	if (!errbuf)
		return -ENOMEM;

	pcap_t *p = pcap_create("ens2f0", errbuf);
	if (!p) {
		printf("pcap_create failed, %s\n");
		goto out;
	} else {
		ret = pcap_activate(p);		
		if (ret > 0) {
			printf("pcap warning: %s\n", pcap_statustostr(ret));
		} else if (ret < 0) {
			pcap_perror(p, "pcap error:");
			goto out;
		}
	}

	ret = pcap_loop(p, 10, handle_packet, NULL);
	printf("\npcap_loop returned: %d\n", ret);
	
out:
	pcap_close(p);
	return 0;
}


