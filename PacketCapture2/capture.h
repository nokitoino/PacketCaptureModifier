#pragma once
#include "structures.h"

void captureToTerminal(pcap_t* handle, int captureAmount);
void captureToFile(pcap_t* handle, int captureAmount);
void cancelCapture(pcap_t* handle);
void resendUDP(pcap_t* handle, int packetnumber);