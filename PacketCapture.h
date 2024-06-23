// PacketCapture.h

#pragma once

#include "include\pcap.h"
#include <windows.h>
#include <vector>
#include <string>

extern pcap_t* adhandle;
extern bool capturing;
extern HWND g_hWnd;

void startCapture(HWND hWnd);
void stopCapture();
void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void captureThread();
void processPackets();
void displayPacket(HWND hWnd, const struct pcap_pkthdr* header, const u_char* pkt_data);
