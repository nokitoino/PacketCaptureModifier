#pragma once
#include "structures.h"
#include <vector>
class Device {
public:
	pcap_if_t* dev = NULL;
	pcap_t* handle = NULL;
	Device();
	Device(const char* filter_exp);
	~Device(); /* free filter and close handler*/
	void open();
	void applyFilter();
	void printDevices();
private:
	std::vector<pcap_if_t> device_list = {};
	pcap_if_t* alldevs = NULL;
	struct bpf_program fp = {0,0};
	bpf_u_int32 net = 0, mask = 0;
	const char* filter_exp = "ip";
	char errbuf[PCAP_ERRBUF_SIZE];
};