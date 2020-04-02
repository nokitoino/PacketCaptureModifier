#include "keyboard.h"

Keyboard::Keyboard() {

}
Keyboard::Keyboard(Device &dev) : device(&dev) {

}
Keyboard::~Keyboard() {
	inputThread.join();
	if (captureThread.joinable()) {
		cancelCapture(device->handle);
		captureThread.join();
	}
}
void Keyboard::test() {
	
}
void Keyboard::getKey() {
	auto fct = [&]() {
		bool active = false;
		while (run) {
			if (GetAsyncKeyState(27) && GetAsyncKeyState(17)) { // maybe some beep signal, might be dangerous
				run = false;
			}
			if (GetAsyncKeyState(112) && !GetAsyncKeyState(17) && !active) { // maybe some beep signal, might be dangerous
				std::cout << "========== Packet to resend ===============> " << std::endl;
				int input;
				std::cin.clear();
				std::cin >> input;
				resendUDP(device->handle,input);
			}
			if (GetAsyncKeyState(113) && !GetAsyncKeyState(17) && !active) { // maybe some beep signal, might be dangerous
				std::cout << "=======================================> WRITE" << std::endl;
				captureThread = std::thread(captureToFile, device->handle, 0);
				active = true;
			}
			if (GetAsyncKeyState(114) && !GetAsyncKeyState(17) && !active) {
				std::cout << "=======================================> ON" << std::endl;
				captureThread = std::thread(captureToTerminal, device->handle, 0);
				active = true;
			}
			if (GetAsyncKeyState(115) && !GetAsyncKeyState(17)  && active) {
				cancelCapture(device->handle);
				captureThread.join();
				std::cout << "=======================================> OFF " << std::endl;
				active = false;

			}

			Sleep(150);
		}
	};
	inputThread = std::thread(fct);
}
