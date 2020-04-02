#pragma once

#include "structures.h"

struct pseudoheader {
	uint32_t arr[3];
};

void fill_pseudoheader(struct pseudoheader& p, uint32_t source, uint32_t destination, u_char reserved, u_char protocol, u_short tcp_length);
u_short calculateTCPChecksum(struct pseudoheader p, const u_short* tcp, int header_size, int payload_size);
u_short calculateIPChecksum(const u_short* ip);