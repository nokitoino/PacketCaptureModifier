#pragma once
#include"device.h"
#include"capture.h"
#include<Windows.h> // GetAsyncKey
#include<thread>
#include<iostream>

class Keyboard {
public:
	Keyboard();
	Keyboard(Device &device);
	~Keyboard();
	void test();
	void getKey();
private:
	bool run = true;
	std::thread inputThread, captureThread;
	Device* device = NULL; // Has to be pointer, beause ~Device() frees only the original device.
};