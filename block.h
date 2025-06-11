#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include "libnet.h"

void forwardBlock(pcap_t* pcap, char* org_pkt, uint8_t* amac, struct LEN_ARGS* len_args);
void backwardBlock(int sockfd, char* org_pkt, uint8_t* amac, struct LEN_ARGS* len_args);