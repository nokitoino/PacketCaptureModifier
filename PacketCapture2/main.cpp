#include"keyboard.h"





char filter_exp[] = "udp port 3074 and less 300"; //udp port 3074 and less 300
int captureAmount = 200;
 
int main() {
	std::cout << "Network Modifier supports TCP and UDP" << std::endl << std::flush;
	std::cout << "This program is based on WinPCAP, and does not support loopback capture." << std::endl << std::flush;
	std::cout << "Developed by Akin Y. [Toge Ka] \n" << std::endl << std::flush;
	
	std::cout << "FN F3 Scan" << std::endl << std::flush;
	std::cout << "FN F4 Stop Scan" << std::endl << std::flush;

	Device device(filter_exp);
	device.open();
	device.applyFilter();

	Keyboard keyboard(device);
	keyboard.getKey();
	return 0;
}