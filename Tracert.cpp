#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <crtdbg.h>
#include <iostream>

using namespace std;

#define ICMP_ECHOREPLY 0   
#define ICMP_ECHOREQ   8

struct IP_hdr
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

struct ICMP_header
{
    unsigned char i_type;
    unsigned char i_code;
    unsigned short i_checksum;
    unsigned short i_id;
    unsigned short i_num;
} IcmpHeader;

unsigned short checksum(unsigned short* addr, int count);

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
    list_adr.sin_port = htons(6666);

    system("pause");
    return 0;
}

unsigned short checksum(unsigned short* addr, int count)
{

    register long sum = 0;

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