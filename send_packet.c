#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

void print_usage()
{
	fprintf(stderr, "usage: [-A <src-MAC>] [-B <dst-MAC>] [-h]\n");
}

int main(int argc, char *argv[])
{
	u_char payload[255] = {0x11, 0x22, 0x11, 0x22, 0x33, 0x44, 0x33, 0x44};
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t ether_tag;
	u_long payload_s = 8;
	u_char *hwsrc;
	u_char *hwdst;
	libnet_t *l;
	int n = 10;
	char *dev;
	int ret;
	int c;
	int i;

	while ((c = getopt(argc, argv, "A:B:p:d:n:h")) != EOF) {
		switch (c) {
			/* send from A to B :) */
			case 'A':
				if ((hwsrc = libnet_hex_aton(optarg, &ret)) == NULL) {
					fprintf(stderr, "Error parsing source MAC\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'B':
				if ((hwdst = libnet_hex_aton(optarg, &ret)) == NULL) {
					fprintf(stderr, "Error parsing destination MAC\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'p':
				strncpy((char *) payload, optarg, sizeof(payload)-1);
				payload_s = strlen((char *) payload);
				break;
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

	l = libnet_init(LIBNET_LINK, dev, errbuf);
	if (!l) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	ether_tag = libnet_build_ethernet(
		hwdst,
		hwsrc,
		ETHERTYPE_IP,
		payload,		/* payload */
		payload_s,		/* payload size */
		l,			/* libnet handle */
		0);			/* libnet id */
	if (ether_tag == -1) {
		fprintf(stderr, "Can't build ethernet hdr: %s",
			libnet_geterror(l));
		ret = EXIT_FAILURE;
		goto out;
	}

	for (i=0; i < n; i++) {
		c = libnet_write(l);
		if (c == -1) {
			fprintf(stderr, "Write error %s\n", libnet_geterror(l));
			ret = EXIT_FAILURE;
			goto out;
		}
		fprintf(stderr, ".", c);
	}
	ret = EXIT_SUCCESS;

out:
	libnet_destroy(l);
	return ret;
}
