#include <stdint.h>
#include "mac.h"

struct Deauthentication {
    uint16_t frameControl = 0x00c0;
    uint16_t duration = 0x013a;
    Mac receiver;
    Mac transmitter;
    Mac BSSID;
    uint16_t num = 0x0000;
};