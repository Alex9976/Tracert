#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

typedef struct IP_hdr
{
    unsigned char verhlen;
    unsigned char tos : 6;
    unsigned char additional : 2;
    unsigned short totallent;
    unsigned short id;
    unsigned short offset;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int source;
    unsigned int destination;
} IpHeader;

typedef struct ICMP_header
{
    unsigned char i_type;
    unsigned char i_code;
    unsigned short i_checksum;
    unsigned short i_id;
    unsigned short i_seq;
} IcmpHeader;

unsigned short checksum(unsigned short* addr, int count);

unsigned int analyze(char* data, SOCKADDR_IN* adr);

int main(int argc, char* argv[])
{
    /*if (argc != 2)
    {
        cout << "Parameters passed incorrectly\n";
        return 1;
    }
    char ending_adr[] = argv[1];
    cout << ending_adr;*/
    char ending_adr[] = "142.250.75.14";
    char* local_adr;

    SOCKADDR_IN list_adr = { 0 };
    list_adr.sin_addr.S_un.S_addr = inet_addr(ending_adr);
    list_adr.sin_family = AF_INET;
    list_adr.sin_port = 0;

    SOCKADDR_IN bnd = { 0 };
    bnd.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    bnd.sin_family = AF_INET;
    bnd.sin_port = 0;

    WSADATA wsd = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
        return 1;

    SOCKET listn = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, WSA_FLAG_OVERLAPPED);
    bind(listn, (sockaddr*)&bnd, sizeof(bnd));
    IcmpHeader pac = { 0 };
    int timeout = 3000;
    setsockopt(listn, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    pac.i_type = 8;
    pac.i_code = 0;
    pac.i_seq = 2;
    pac.i_checksum = 0;
    pac.i_id = (USHORT)GetCurrentProcessId();
    int size = sizeof(pac) + 32;
    char* Icmp = new char[size];
    memcpy(Icmp, &pac, sizeof(pac));
    memset(Icmp + sizeof(pac), 'A', 32);

    IcmpHeader* Packet = (IcmpHeader*)Icmp;
    Packet->i_checksum = checksum((USHORT*)Packet, size);
    char buf[256] = { 0 };
    int outlent = sizeof(SOCKADDR_IN);
    SOCKADDR_IN out_ = { 0 };
    out_.sin_family = AF_INET;

    unsigned int control = list_adr.sin_addr.S_un.S_addr;

    cout << "Route to " << ending_adr << " with 30 hops\n";
    for (int i = 1; i <= 30; i++)
    {
        setsockopt(listn, IPPROTO_IP, IP_TTL, (char*)&i, 4);
        int bytes = sendto(listn, (char*)Packet, size, 0, (sockaddr*)&list_adr, sizeof(list_adr));
        Sleep(1000);

        if (recvfrom(listn, buf, 256, 0, (sockaddr*)&out_, &outlent) == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                cout << "Request timeout\n";
                continue;
            }
        }
        cout.width(5);
        cout << left << i;
        if (analyze(buf, &out_) == control)
            break;
        memset(buf, 0, 0);
    }

    delete[] Icmp;
    closesocket(listn);
    WSACleanup();

    system("pause");
    return 0;
}

unsigned short checksum(unsigned short* addr, int count)
{
    long sum = 0;

    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }
    if (count > 0)
        sum += *(unsigned char*)addr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned int analyze(char* data, SOCKADDR_IN* adr)
{
    char* ip;
    IpHeader* packet = (IpHeader*)data;

    ip = inet_ntoa(adr->sin_addr);

    cout.width(20);
    cout << left << ip << "\n";
    return packet->source;

}