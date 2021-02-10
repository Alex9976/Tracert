#include <iostream>

using namespace std;

struct ICMP_header
{
    unsigned char i_type;
    unsigned char i_code;
    unsigned short i_checksum;
    unsigned short i_id;
    unsigned short i_num;
} IcmpHeader;

int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        cout << "\nUsage: tracert.exe endName\n";
        return 1;
    }
    else if (argc != 2)
    {
        cout << "Parameters passed incorrectly\n";
        return 1;
    }
    string ending_adr = argv[1];
    cout << ending_adr;

}
