// PacketCapture.cpp

#include "PacketCapture.h"
#include <queue>
#include <thread>
#include <mutex>
#include <commctrl.h>
#include <iostream>
#include "resource.h"

pcap_t* adhandle;  // Handle for the packet capture session
char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages
bool capturing = false;
HWND g_hWnd = nullptr;

// Packet queue and synchronization
std::queue<std::pair<pcap_pkthdr, std::vector<u_char>>> packetQueue;
std::mutex queueMutex;

void displayPacket(HWND hWnd, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    HWND hList = GetDlgItem(hWnd, IDC_PACKET_LIST);

    LVITEM lvItem;
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = ListView_GetItemCount(hList);
    lvItem.iSubItem = 0;
    lvItem.pszText = new WCHAR[256];
    swprintf(lvItem.pszText, 256, L"%ld", header->ts.tv_sec);
    ListView_InsertItem(hList, &lvItem);

    lvItem.iSubItem = 1;
    swprintf(lvItem.pszText, 256, L"%d", header->len);
    ListView_SetItem(hList, &lvItem);

    lvItem.iSubItem = 2;
    swprintf(lvItem.pszText, 256, L"%S", pkt_data);
    ListView_SetItem(hList, &lvItem);

    delete[] lvItem.pszText;
}

void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    std::lock_guard<std::mutex> lock(queueMutex);
    packetQueue.push({ *header, std::vector<u_char>(pkt_data, pkt_data + header->len) });
}

void captureThread()
{
    pcap_loop(adhandle, 0, packetHandler, nullptr);
}

void processPackets()
{
    while (capturing)
    {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            while (!packetQueue.empty())
            {
                auto packet = packetQueue.front();
                packetQueue.pop();
                displayPacket(g_hWnd, &packet.first, packet.second.data());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void startCapture(HWND hWnd)
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    std::string adaptersList = "Available Adapters:\n";

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        MessageBoxA(hWnd, errbuf, "Error in pcap_findalldevs", MB_OK);
        return;
    }

    for (d = alldevs; d; d = d->next) {
        adaptersList += d->name;
        adaptersList += "\n";
        if (d->flags & PCAP_IF_LOOPBACK) {
            continue;
        }
        break; // Use the first non-loopback device
    }

    MessageBoxA(hWnd, adaptersList.c_str(), "Available Adapters", MB_OK);

    if (d == nullptr) {
        MessageBox(hWnd, L"No suitable adapter found", L"Error", MB_OK);
        pcap_freealldevs(alldevs);
        return;
    }

    MessageBoxA(hWnd, d->name, "Selected Adapter", MB_OK);

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr) {
        MessageBox(hWnd, L"Unable to open the adapter", L"Error", MB_OK);
        pcap_freealldevs(alldevs);
        return;
    }

    struct bpf_program fcode;
    if (pcap_compile(adhandle, &fcode, "", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        MessageBoxA(hWnd, pcap_geterr(adhandle), "Unable to compile the packet filter", MB_OK);
        pcap_close(adhandle);
        return;
    }

    if (pcap_setfilter(adhandle, &fcode) == -1) {
        MessageBoxA(hWnd, pcap_geterr(adhandle), "Error setting the filter", MB_OK);
        pcap_close(adhandle);
        return;
    }

    pcap_freealldevs(alldevs);

    capturing = true;
    std::thread capture(captureThread);
    capture.detach();
    std::thread processor(processPackets);
    processor.detach();
}

void stopCapture()
{
    capturing = false;
    if (adhandle) {
        pcap_breakloop(adhandle);
        pcap_close(adhandle);
        adhandle = nullptr;
    }
}

// Main function to test packet capturing functions
int main()
{
    // For testing purposes, we'll create a dummy window handle
    HWND hWnd = GetConsoleWindow();

    // Test startCapture
    std::cout << "Starting packet capture..." << std::endl;
    startCapture(hWnd);

    // Allow capture to run for a short period
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Test stopCapture
    std::cout << "Stopping packet capture..." << std::endl;
    stopCapture();

    // Indicate that the test is complete
    std::cout << "Packet capture test complete." << std::endl;

    return 0;
}
