#pragma once

#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t SrcPort_;
	uint16_t DstPort_;
	uint32_t seq_;
	uint32_t ack_;
	uint8_t reserved:4;
	uint8_t offset:4;
	uint8_t flag;
	uint16_t window;
	uint16_t checksum_;
	uint16_t urgentPointer;

    uint16_t SrcPort() { return ntohs(SrcPort_); }
    uint16_t DstPort() { return ntohs(DstPort_); }
	uint32_t seq() { return ntohl(seq_); }
	uint32_t ack() { return ntohl(ack_); }
	uint16_t checksum() {  return ntohs(checksum_); }

	static uint16_t calcChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr);
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)