#include "device.h"
#include "checksum.h"
#include  <iomanip>
#include <sstream>
#include <algorithm>    // std::remove_if
std::ofstream packetFile;
bool writeToFile = false;
static int count = 0;                  /* packet counter */


void
got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{


	/* declare pointers to packet headers */
	const struct sniff_ethernet* ethernet;  /* The ethernet header [1] */
	struct sniff_ip* ip;              /* The IP header */
	const struct sniff_tcp* tcp;            /* The TCP header */
	const struct sniff_udp* udp;
	const u_char* payload;                    /* Packet payload */

	int size_ip = 0;
	int size_tcp = 0;
	int size_udp = 0;
	int size_payload = 0;
	std::cout << "\n\nPackage captured " << count << std::endl;
	count++;
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);	
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	size_ip = IP_HL(ip) * 4; //IP HEADER-LENGTH, ipv4
	std::cout << "IP Header length : " << size_ip << std::endl;

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	/* print source and destination IP addresses */
	itoip4_s(ntohl(ip->ip_src));
	itoip4_s(ntohl(ip->ip_dst));
	std::cout << "Entire Length: " << header->len << std::endl;
	auto fct_tcp = [&]() {
		/* define/compute tcp header offset */
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip); // 14 + 24 + 
		std::cout << "Seq: " << ntohl(tcp->th_seq) << std::endl;

		std::cout << "Ack: " << ntohl(tcp->th_ack) << std::endl;
		size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));

		/* define/compute tcp payload (segment) offset */
		payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

		/*
		 * Print payload data; it might be binary, so don't just
		 * treat it as a string.
		 */
		if (size_payload > 0) {
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}
		else if (size_payload == 0) {
			std::cout << "Payload empty" << std::endl;
		}
	};
	auto fct_udp = [&]() {
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		payload = packet + SIZE_ETHERNET + size_ip + 8;
		size_udp = ntohs(udp->length);
		std::cout << "UDP Source Port " << ntohs(udp->udp_sport) << std::endl;
		std::cout << "UDP Destination Port " << ntohs(udp->udp_dport) << std::endl;
		size_payload = ntohs(udp->length) - 8; // UDP Header 8 Bytes
		if (size_payload > 0) {

			std::cout << "	Payload (" << size_payload << "bytes):\n" << std::endl;
			print_payload(payload, size_payload);
		}
		else if (size_payload == 0) {
			std::cout << "Payload empty" << std::endl;
		}

	};



	/* determine protocol */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("   Protocol: TCP\n");
		fct_tcp();
		break;
	case IPPROTO_UDP:
		printf("   Protocol: UDP\n");
		fct_udp();
		break;
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
	if (writeToFile) { // write Packets of TCP UDP into file and seperate payload with ' '
		if (!packetFile) {
			std::cout << "Couldn't open packets.txt" << std::endl;
		}
		else {
			const u_char* ptr = packet;
			std::cout << "HEADER LENGTH " << header->len << " Size Payload: " << size_payload << std::endl;
			for (u_int i = 0; i < header->len; i++) {
				if (i == (header->len - size_payload)) {
					packetFile << ' '; // seperate payload with space
				}
				packetFile << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)(*ptr); // 0x0F instead 0xF -.- iostream sucks
				ptr++;
			}
			packetFile << std::dec << "," << count << std::endl;

		}
	}
	/*
	 *  OK, this packet is TCP.
	 */

	


	return;
}

int char2int(char input) {
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'a' && input <= 'f')
		return input - 'W';
	if (input >= 'A' && input <= 'F')
		return input - '7';

	std::cout << input << std::endl;
}


void hexStringToUChar(u_char* packet, std::string packet_content) {
	char* packet_char = &packet_content[0];
	for (int i = 0; i < packet_content.length();i++) {
		packet[i] = (char2int(packet_char[i]) << 4) + char2int(packet_char[i + 1]);
	}
}

void resendUDP(pcap_t* handle, int packetnumber) {
	std::ifstream packetFile_r;
	packetFile_r.open("packets.txt");
	std::string packet_content;
	int counter = 0;

	while (std::getline(packetFile_r, packet_content)){
		packet_content.erase(std::remove_if(packet_content.begin(), packet_content.end(), isspace), packet_content.end());
		std::cout << packet_content << std::endl;
		if (counter == packetnumber) {
			std::stringstream s(packet_content);
			std::getline(s, packet_content, ','); // packet_content got real content now
			u_char* packet = new u_char[packet_content.length()];
			hexStringToUChar(packet, packet_content);
			/*Stichprobe hier*/
			pcap_loop(handle,10,stichprobe,NULL);
			pcap_sendpacket(handle, packet, (int)packet_content.length());
			delete[] packet;
			std::cout << "(===================> SENT >================)" << std::endl;
			break;
		}
		
		counter++;
	}


}
void captureToFile(pcap_t* handle, int captureAmount) {
	count = 0;
	packetFile.open("packets.txt", std::ios_base::out);
	writeToFile = true;
	pcap_loop(handle, captureAmount, got_packet, NULL);
}
void captureToTerminal(pcap_t* handle, int captureAmount) {
	pcap_loop(handle, captureAmount, got_packet, NULL);
}
void cancelCapture(pcap_t* handle) {
	pcap_breakloop(handle);
	if (packetFile) {
		packetFile.close();
	}
}