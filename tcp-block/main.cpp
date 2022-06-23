#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>


#define TCP 0x06
#define HTTP 0x50
#define HTTPS 443
#define SPACEBAR 0x20

#define ACK 0x10
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

#pragma pack(push, 1)
struct SendPacketHdr final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char msg[100];
};

struct IpPacket final{
    EthHdr eth_;
    IpHdr ip_;
};

typedef struct
{
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL };

Mac my_mac;
#pragma pack(pop)

void usage() {
    printf("syntax : ./tcp-block <interface> <pattern>\n");
    printf("sample : ./tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool parse(Param* param, int argc, char* argv[])
{
    if (argc != 3) {
        usage();
        return -1;
    }

    param->dev_ = argv[1];
    return true;
}

char *strnstr(const char *haystack, const char *needle, size_t len)
{
        int i;
        size_t needle_len;

        if (0 == (needle_len = strnlen(needle, len)))
                return (char *)haystack;

        for (i=0; i<=(int)(len-needle_len); i++)
        {
                if ((haystack[0] == needle[0]) &&
                        (0 == strncmp(haystack, needle, needle_len)))
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

void SendPacket(pcap_t* handle, const u_char* org_packet, int caplen, Mac smac, Mac dmac,
                int ttl, Ip sip, Ip dip, uint16_t srcport, uint16_t dstport, 
                uint32_t seq, uint32_t ack, char flag,
                char* FinMessage, int m_len, bool isForward)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    u_char* packet = (u_char*)malloc(sizeof(u_char) * caplen);
    memcpy(packet, org_packet, caplen);
    IpPacket* iphdr = (IpPacket*) packet;

    int packetLen = 14 + (iphdr->ip_.IHL * 4) + sizeof(TcpHdr);
    int TcpDataLen = caplen - packetLen;

    // Ethernet header
    iphdr->eth_.smac_ = smac;
    iphdr->eth_.dmac_ = dmac;

    // IP header
    iphdr->ip_.length_ = htons(packetLen - 14);
    iphdr->ip_.TTL = ttl;
    iphdr->ip_.sip_ = sip;
    iphdr->ip_.dip_ = dip;

    // TCP header
    TcpHdr* tcphdr = (TcpHdr*) ((char*)packet + 14 + iphdr->ip_.IHL * 4);
    tcphdr->SrcPort_ = srcport;
    tcphdr->DstPort_ = dstport;
    
    if(isForward) {
        tcphdr->seq_ = htonl(tcphdr->seq() + TcpDataLen);
        tcphdr->ack_ = ack;
    } else {
        tcphdr->ack_ = htonl(tcphdr->seq() + TcpDataLen);
        tcphdr->seq_ = ack;
    }
    
    tcphdr->offset = sizeof(TcpHdr) >> 2;
    tcphdr->flag = flag;

    if(m_len != 0) {
        packetLen += m_len;
        iphdr->ip_.length_ = htons(iphdr->ip_.length() + m_len);
        char* FinM = (char*) tcphdr + sizeof(TcpHdr);
        memcpy(FinM, FinMessage, m_len);
    }

    iphdr->ip_.checksum_ = htons(IpHdr::calcChecksum(&(iphdr->ip_)));
    tcphdr->checksum_ = htons(TcpHdr::calcChecksum(&(iphdr->ip_), tcphdr));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet), packetLen);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    free(packet);
}

int HttpBlock(pcap_t* handle, const u_char* org_packet, int caplen)
{
    IpPacket* org_pkt = (IpPacket*) org_packet;
    TcpHdr* tcp_pkt = (TcpHdr*)((char*)(&(org_pkt->ip_))+ (org_pkt->ip_.IHL * 4));
    char flag;
    char* FinMessage;

    // forward
    flag = RST | ACK;
    SendPacket(handle, org_packet, caplen, my_mac, org_pkt->eth_.dmac_,
                org_pkt->ip_.TTL, org_pkt->ip_.sip_, org_pkt->ip_.dip_, tcp_pkt->SrcPort_, tcp_pkt->DstPort_,
                tcp_pkt->seq_, tcp_pkt->ack_, flag, 
                FinMessage, 0, true);

    // backward
    flag = FIN | ACK;
    FinMessage = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    SendPacket(handle, org_packet, caplen, my_mac, org_pkt->eth_.smac_,
                0x80, org_pkt->ip_.dip_, org_pkt->ip_.sip_, tcp_pkt->DstPort_, tcp_pkt->SrcPort_, 
                tcp_pkt->seq_, tcp_pkt->ack_, flag, 
                FinMessage, strlen(FinMessage), false);

}

int HttpsBlock(pcap_t* handle, const u_char* org_packet, int caplen)
{
    IpPacket* org_pkt = (IpPacket*) org_packet;
    TcpHdr* tcp_pkt = (TcpHdr*)((char*)(&(org_pkt->ip_))+ (org_pkt->ip_.IHL * 4));
    char flag;
    char* FinMessage;

    // forward
    flag = RST | ACK;
    SendPacket(handle, org_packet, caplen, my_mac, org_pkt->eth_.dmac_,
                org_pkt->ip_.TTL, org_pkt->ip_.sip_, org_pkt->ip_.dip_, tcp_pkt->SrcPort_, tcp_pkt->DstPort_,
                tcp_pkt->seq_, tcp_pkt->ack_, flag, 
                FinMessage, 0, true);

    // backward
    SendPacket(handle, org_packet, caplen, my_mac, org_pkt->eth_.dmac_,
                org_pkt->ip_.TTL, org_pkt->ip_.sip_, org_pkt->ip_.dip_, tcp_pkt->SrcPort_, tcp_pkt->DstPort_,
                tcp_pkt->seq_, tcp_pkt->ack_, flag, 
                FinMessage, 0, false);
}

void FindMyMac(void)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    //I want IP address attached to "enp0s3"
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);

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
    my_mac = Mac(temp);
}

int main(int argc, char* argv[]) {

    if (!parse(&param, argc, argv))
        return -1;
    FindMyMac();

    char* dev = argv[1];
    char* pattern = argv[2];
    printf("pattern = %s\n", pattern);
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* r_packet;

        handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
        res = pcap_next_ex(handle, &header, &r_packet);
        IpPacket* receivePacket = (IpPacket*) r_packet;

        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            continue;
        }
        else if (receivePacket->ip_.protocol == TCP) {

            // TCP Packet Caught
            struct TcpHdr* tcp = (TcpHdr*)((char*)(&receivePacket->ip_) + (receivePacket->ip_.IHL * 4));
            char* tcpData = (char*)tcp + (tcp->offset * 4);
            int offset = tcpData - (char*)(receivePacket);
            int len = header->caplen - offset;

            // HTTP
            if ( (tcp->SrcPort() == HTTP) || (tcp->DstPort() == HTTP) ) {
    
                // Check Existence of Pattern in TcpData
                if (len > 0) {
                    char* site = strnstr(tcpData, pattern, len);
                    if(site) {
                        printf("Pattern Caught in HTTP\n");
                        HttpBlock(handle, r_packet, header->caplen);
                    }
                }
            }

            // HTTPS
            else if ( (tcp->SrcPort() == HTTPS) || (tcp->DstPort() == HTTPS) ) {
       
                // Check Existence of Pattern in TcpData
                if (len > 0) {
                    char* site = strnstr(tcpData, pattern, len);
                    if(site) {
                        printf("Pattern Caught in HTTPS\n");
                        HttpsBlock(handle, r_packet, header->caplen);
                    }
                }
            }
        }
    }
}