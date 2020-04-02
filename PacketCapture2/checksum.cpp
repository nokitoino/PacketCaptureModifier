
#include "checksum.h"

void fill_pseudoheader(struct pseudoheader& p, uint32_t source, uint32_t destination, u_char reserved, u_char protocol, u_short tcp_length) {

	p.arr[0] = source;
	p.arr[1] = destination;
	uint32_t a = reserved;
	a = a << 8;
	a += protocol;
	a = a << 16;
	a += tcp_length; //computed length is in host order, we need to reverse	
	p.arr[2] = htonl(a);

}
u_short calculateTCPChecksum(struct pseudoheader p, const u_short* tcp, int header_size, int payload_size) {
	u_short checksum = 0;

	/* Adding 96 Bit Pseudo-Header in 16 bit fragments*/
	u_short* a = reinterpret_cast<u_short*>(p.arr);
	for (int i = 0; i < 6; i++) {
		if (checksum + *a > 0xFFFF) {
			checksum += *a;
			checksum += 0x0001;
			a++;
		}
		else {
			checksum += *a;
			a++;
		}
	}
	/* Sum of TCP-Header + Payload in 16 bit fragments */

	int padding = (header_size + payload_size) * 8 % 16; // Byte to Bits and modulo 16 Bits, gives padding amount in bits to extend to pure 16 bit fragments
	for (int i = 0; i < ((header_size + payload_size) * 8 + padding) / 16; i++) { // inclusive padding, how many 16 bit iterations
		if (i == 8) {	// we skip checksum (can confirm he lands on checksum here)
			tcp++;
			continue;
		}
		if (i == ((header_size + payload_size) * 8 + padding) / 16 - 1) { // very important! last iteration
			u_short mask = 0xFFFF;
			mask = mask >> padding;
			if (checksum + (*tcp & mask) > 0xFFFF) {
				checksum += (*tcp & mask);
				checksum += 0x0001;

			}
			else {
				checksum += (*tcp & mask);

			}
			break;
		}
		if (checksum + *tcp > 0xFFFF) {
			checksum += *tcp;
			checksum += 0x0001;
			tcp++;
		}
		else {
			checksum += *tcp;
			tcp++;
		}
	}

	return ~checksum;
}
u_short calculateIPChecksum(const u_short* ip) {
	u_short checksum = 0;
	for (int i = 0; i < 10; i++) { //20 Bytes = 160 Bits => 160 Bits / 16 Bits = 10. 10 fragments of 16 bits

		if (i == 5) {
			ip++;
			continue;
		}
		if ((checksum + *ip) > 0xFFFF) { //ones complement condition
			checksum += *ip;
			checksum += 0x0001;
		}
		else {
			checksum += *ip;
		}
		ip++;

	}
	return ~checksum;
}