#include "device.h"

Device::Device() {
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "Could not find any device" << errbuf << std::endl;
		exit(1);
	}
	dev = alldevs->next; // remove or add more ->next to find your device! ********************************
}
Device::Device(const char* expression) : filter_exp(expression) {
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "Could not find any device" << errbuf << std::endl;
		exit(1);
	}
	dev = alldevs->next; // remove or add more ->next to find your device!  ********************************
}

Device::~Device() {
	pcap_freecode(&fp);
	pcap_close(handle);
}

void Device::printDevices() {

}
void Device::open() {

	handle = pcap_open_live(dev->name, BUFSIZ, 0, 1000, errbuf); // ********** BYTE SIZE VIELFACHES von 2 BYTES, weil PAYLOAD aus 16 bit fragmenten besteht

	pcap_setdirection(handle, PCAP_D_OUT);
	if (handle == NULL) {
		std::cerr << "Could not open the device " << errbuf << std::endl;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		std::cout << "Device does not support 802.3 Ethernet 2 " << errbuf << std::endl;
	}
}
void Device::applyFilter() {
	if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
		std::cerr << "Netmask not found " << errbuf << std::endl;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		std::cerr << "Filter expression is wrong : " << filter_exp << std::endl;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		std::cerr << "Filter could not be applied  " << filter_exp << std::endl;
	}

	pcap_setdirection(handle, PCAP_D_OUT);
}
