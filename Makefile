all: send_packet is_legacy

send_packet: send_packet.c
	gcc -lnet -o send_packet send_packet.c

is_legacy: is_legacy.c
	gcc -lpcap -o is_legacy is_legacy.c

clean:
	rm send_packet is_legacy
