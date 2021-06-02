# PacketCaptureModifier
This application was written in C++ with the PCAP Framework and captures network packets from the Data Link Layer. It manually calculates checksum of IP/TCP/UDP and is capable to resend unencrypted modified packets.
The PCM can capture and display the traffic directly on the console, or offers the possibility to save the traffic into a file in HEX format.

Requirements:
WinPCAP SDK needs to be installed in order to develop and run this application.

Adjustments:
First of all, you have to link the project with WinPCAP.
Small explanation for Visual Studio:
Property -> C/C++ ->General->Include: \Include of WinPCAP SDK.
Property -> C/C++ ->Preprocessor: WPCAP;WIN32
Property -> Linker -> Additional Libraries: \Lib\x64 or \x86 of WinPCAP SDK.

In the main.cpp file you have to adjust a costum filter analog to Wireshark.

Purpose:
The main purpose of this project is to show how to use the fundamentals of PCAP in C++ and apply low-level Networking knowledge onto the capture process, like calculating manually the checksum of different protocols.
 
