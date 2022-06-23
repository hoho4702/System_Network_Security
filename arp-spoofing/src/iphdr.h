#pragma once

#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint16_t temp[6];
    Ip sip_;
    Ip dip_;

    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }

};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
