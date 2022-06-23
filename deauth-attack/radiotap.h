#include <stdint.h>

struct RadiotapHdr {
    uint8_t revision = 0x0;
    uint8_t pad = 0x0;
    uint16_t length = 0x000c;
    uint32_t flag = 0x00008004;
    uint8_t rate = 0x02;
    uint8_t temp1 = 0x00;
    uint8_t temp2 = 0x18;
    uint8_t temp3 = 0x00;
};