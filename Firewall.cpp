// Firewall.cpp : Defines the entry point for the application.
//

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <pcap.h>
#include "framework.h"
#include "Firewall.h"
#include "resource.h"
#include <string>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

// Packet capture related variables
pcap_t* adhandle;  // Handle for the packet capture session
char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_FIREWALL, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_FIREWALL));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;
    //Size of the WNDCLASSEX structure.
    wcex.cbSize = sizeof(WNDCLASSEX);
    //indicates the window should be redrawn if resized horizontally or vertically
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    //Pointer to the window procedure.
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    //Handle to the application instance.
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_FIREWALL));
    //Handle to the cursor.
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_FIREWALL);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable
   // Initialize common controls.
   INITCOMMONCONTROLSEX icex;
   icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
   icex.dwICC = ICC_LISTVIEW_CLASSES;
   InitCommonControlsEx(&icex);

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   // Create UI controls
   CreateWindowW(L"BUTTON", L"Start Capture", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
       10, 10, 150, 30, hWnd, (HMENU)IDC_START_BUTTON, hInstance, nullptr);

   CreateWindowW(L"BUTTON", L"Stop Capture", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
       170, 10, 150, 30, hWnd, (HMENU)IDC_STOP_BUTTON, hInstance, nullptr);

   HWND hList = CreateWindowW(WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
       10, 50, 760, 500, hWnd, (HMENU)IDC_PACKET_LIST, hInstance, nullptr);

   // Initialize the list view columns
   LVCOLUMN lvCol;
   lvCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
   lvCol.cx = 200;
   lvCol.pszText = (LPWSTR)L"Time";
   ListView_InsertColumn(hList, 0, &lvCol);
   lvCol.pszText = (LPWSTR)L"Length";
   ListView_InsertColumn(hList, 1, &lvCol);
   lvCol.pszText = (LPWSTR)L"Data";
   ListView_InsertColumn(hList, 2, &lvCol);

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

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
    HWND hWnd = (HWND)param;
    displayPacket(hWnd, header, pkt_data);
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

    // Iterate over the device list and find a suitable adapter
    for (d = alldevs; d; d = d->next) {
        adaptersList += d->name;
        adaptersList += "\n";
        if (d->flags & PCAP_IF_LOOPBACK) {
            // Skip loopback devices
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
    // Set a filter to capture all packets
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
    pcap_loop(adhandle, 0, packetHandler, reinterpret_cast<u_char*>(hWnd));
}

void stopCapture()
{
    if (adhandle) {
        pcap_breakloop(adhandle);
        pcap_close(adhandle);
        adhandle = nullptr;
    }
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDC_START_BUTTON:
            startCapture(hWnd);
            break;
        case IDC_STOP_BUTTON:
            stopCapture();
            break;
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
    }
    break;
    case WM_DESTROY:
        stopCapture();
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
