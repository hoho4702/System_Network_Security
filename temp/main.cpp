#include <cstdio>
#include <pcap.h>
#include "mac.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include <map>
#include <tuple>

#define Beacon 0x80
#define Data 0x0020

using namespace std;

#pragma pack(push, 1)
typedef struct
{
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL };

#pragma pack(pop)

map<Mac, tuple<int, int, char*>> info;

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

bool parse(Param* param, int argc, char* argv[])
{
    if (argc != 2) {
        usage();
        return false;
    }

    param->dev_ = argv[1];
    return true;
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int num = 0;
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* r_packet;

        handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
        res = pcap_next_ex(handle, &header, &r_packet);
        // printf("captured packet num = %d\n", ++num);
        // continue;


        char* airodump = (char*)r_packet;
        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            continue;
        }
        else {
    
            uint16_t length = (*(airodump+2));
            int pwr;
            uint8_t type;
            Mac BSSID;
            uint16_t ssidLen;
            char* SSID;

            if(length == 0x20) {
                pwr = (int)*(airodump+0x16); // pwr
                type = *(airodump+0x20); // type
                if(type == Beacon) {

                    BSSID = *(Mac*)(airodump+0x30);

                    ssidLen = ntohs(*(uint16_t*)(airodump+0x44));
                    SSID = (char*)malloc(sizeof(char) * (ssidLen + 1));
    
                    strncpy(SSID, airodump+0x46, ssidLen);
                    SSID[ssidLen] = 0;
                    if(!*SSID) continue;
                    SSID[ssidLen] = '\0';

                    // new BSSID
                    auto iter = info.find(BSSID);
                    if(iter == info.end()) {
                        info.insert({BSSID, make_tuple(pwr, 1, SSID)});
                    } else { // already existed
                        get<0>((*iter).second) += pwr;
                        get<1>((*iter).second) += 1;
                    }
                    system("clear");
                    printf("       BSSID         PWR    Beacons       ESSID\n\n");
                    std::map<Mac,tuple<int, int, char*>>::iterator it;
                    for(it = info.begin(); it != info.end(); it++) {
                        printf("%s    ", std::string((*it).first).data());
                        printf("%d       ", get<0>((*it).second) / get<1>((*it).second));
                        printf("%d      ", get<1>((*it).second));
                        printf("%s\n", get<2>((*it).second));
                    }
                }
            }
        }
    }
}