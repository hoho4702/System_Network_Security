#pragma once

#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t IHL:4;
    uint8_t version:4;
    uint8_t TOS;
    uint16_t length_;
    uint8_t temp[4];
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum_;
    Ip sip_;
    Ip dip_;

    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }
    uint16_t length() { return ntohs(length_); }
    uint16_t checksum() { return ntohs(checksum_); }

    static uint16_t calcChecksum(IpHdr* ipHdr);
	static uint16_t recalcChecksum(uint16_t oldChecksum, uint16_t oldValue, uint16_t newValue);
	static uint16_t recalcChecksum(uint16_t oldChecksum, uint32_t oldValue, uint32_t newValue);
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)