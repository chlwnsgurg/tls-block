#include <cstdio>
#include <string>
#include <map>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "tlshdr.h"

#include "block.h"

struct Key {
	uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    bool operator<(const Key& r) const{
         return std::tie(src_ip, src_port, dst_ip, dst_port) < std::tie(r.src_ip, r.src_port, r.dst_ip, r.dst_port);
    }
};

struct ParsedData {
    std::string data;
    size_t total_len = 0;
    size_t current_len = 0;
};

std::map<Key, ParsedData> tls_buffer;

bool get_ip(char* dev, char* ip) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}
	
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, 4*Ip::SIZE);
	close(sfd);
	return true;
}

bool get_mac(char* dev, uint8_t* mac) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	close(sfd);
	return true;
}

static uint16_t compute_checksum(uint16_t *addr, uint32_t count) {
    uint32_t sum = 0;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += (*addr & 0xFF00);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum & 0xFFFF;
}

void compute_ip_checksum(struct IpHdr *ip_hdr){
    ip_hdr->checksum_ = 0;
    ip_hdr->checksum_ = compute_checksum(reinterpret_cast<uint16_t*>(ip_hdr), ip_hdr->ihl() << 2);
}

void compute_tcp_checksum(IpHdr *ip_hdr, TcpHdr *tcp_hdr, uint8_t *data, size_t data_len){
    uint32_t sum = 0;
    const uint16_t tcp_len = sizeof(TcpHdr) + data_len;

    // Pseudo header
    sum += (ip_hdr->src_ip_ >> 16) & 0xFFFF;
    sum += ip_hdr->src_ip_ & 0xFFFF;
    sum += (ip_hdr->dst_ip_ >> 16) & 0xFFFF;
    sum += ip_hdr->dst_ip_ & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // TCP header
    tcp_hdr->checksum_ = 0; // Initialize checksum to 0
    const uint16_t *tcp_ptr = reinterpret_cast<uint16_t*>(tcp_hdr);
    size_t tcp_words = sizeof(TcpHdr) / 2;

    for (size_t i = 0; i < tcp_words; i++) {
        sum += tcp_ptr[i];
    }

    // TCP payload (data)
    const uint16_t *data_ptr = reinterpret_cast<const uint16_t*>(data);
    size_t data_words = data_len / 2;

    for (size_t i = 0; i < data_words; i++) {
        sum += data_ptr[i];
    }

    // Handle odd-length data (pad last byte)
    if (data_len % 2) {
        sum += *(reinterpret_cast<const uint8_t*>(data) + data_len - 1);
    }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;

    tcp_hdr->checksum_ = static_cast<uint16_t>(sum);
}

std::string extract_sni(const uint8_t *tls_data, size_t tls_data_len) {
    size_t offset = sizeof(TlsRecordHdr) + sizeof(TlsHandshakeHdr);

    if (offset + 2 > tls_data_len) return ""; // Version
    offset += 2;

    if (offset + 32 > tls_data_len) return ""; // Random
    offset += 32;

    if (offset + 1 > tls_data_len) return ""; // Session ID length
    uint8_t session_id_len = tls_data[offset++];
    if (offset + session_id_len > tls_data_len) return "";
    offset += session_id_len;

    if (offset + 2 > tls_data_len) return ""; // Cipher suites length
    uint16_t cipher_suites_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
    offset += 2 + cipher_suites_len;

    if (offset + 1 > tls_data_len) return ""; // Compression methods length
    uint8_t compression_len = tls_data[offset++];
    offset += compression_len;

    if (offset + 2 > tls_data_len) return ""; // Extensions length
    uint16_t extensions_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
    offset += 2;

    // Parsing Extensions
    size_t extensions_end = offset + extensions_len;
    while (offset + 4 <= extensions_end && offset + 4 <= tls_data_len) {
        uint16_t ext_type = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset));
        uint16_t ext_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + offset + 2));
        offset += 4;

        if (ext_type == TLS_EXTENSION_SERVER_NAME && offset + ext_len <= tls_data_len) {
            // Parsing Server Name Extension
            size_t sni_offset = offset;
            if (sni_offset + 2 > tls_data_len) break;

            uint16_t server_name_list_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + sni_offset));
            sni_offset += 2;

            if (sni_offset + server_name_list_len > tls_data_len) break;

            while (sni_offset + 3 <= offset + ext_len && sni_offset + 3 <= tls_data_len) {
                uint8_t name_type = tls_data[sni_offset++];
                uint16_t name_len = ntohs(*reinterpret_cast<const uint16_t*>(tls_data + sni_offset));
                sni_offset += 2;

                if (name_type == TLS_SERVER_NAME_TYPE_HOSTNAME && sni_offset + name_len <= tls_data_len) {
                    return std::string(reinterpret_cast<const char*>(tls_data + sni_offset), name_len);
                }
                sni_offset += name_len;
            }
        }
        offset += ext_len;
    }

    return "";
}

void usage() {
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

typedef struct {
	char* dev_;
	char* pattern_;
} Param;
Param param;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->pattern_ = argv[2];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)) return -1;
	
	// RAW SOCKET OPEN
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		perror("Error: raw socket creation failed");
		return -1;
    }
    				
    int value = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value)) < 0){
		perror("setsockopt");
		close(sockfd);
		return -1;
    }

	// tls_block
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, -1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error: couldn't open device %s(%s)\n", param.dev_, errbuf);
		return -1;
	}

	uint8_t amac[Mac::SIZE]; get_mac(param.dev_, amac);
    struct pcap_pkthdr *header;
    const u_char *packet;

	printf("[+] TLS Block started - %s\n", param.pattern_);
	while (true) {
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
		
		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(eth_hdr+1);
		if(ipv4_hdr->ip_p != IPTYPE_TCP) continue;
		uint16_t ipv4_hdr_len = 4*(ipv4_hdr->ip_hl);

		
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((char*)ipv4_hdr + ipv4_hdr_len);
		uint16_t tcp_hdr_len = 4*tcp_hdr->th_off;
		uint32_t payload_len = ntohs(ipv4_hdr->ip_len) - ipv4_hdr_len - tcp_hdr_len;
		uint8_t* tcp_data = (u_int8_t*)tcp_hdr + tcp_hdr_len;
		
		Key key = {
			ipv4_hdr->ip_src.s_addr, tcp_hdr->th_sport, ipv4_hdr->ip_dst.s_addr, tcp_hdr->th_dport
        };

        if (tls_buffer.find(key) == tls_buffer.end()) {

            // If new TLS connection
            if (payload_len < sizeof(TlsRecordHdr) + sizeof(TlsHandshakeHdr)) continue;
            const TlsRecordHdr *tls_record = reinterpret_cast<const TlsRecordHdr*>(tcp_data);
            if (!tls_record->is_tls() || tls_record->type() != TlsRecordHdr::Handshake) continue;
            const TlsHandshakeHdr *tls_handshake = reinterpret_cast<const TlsHandshakeHdr*>(tcp_data + sizeof(TlsRecordHdr));
            if (tls_handshake->type() != TlsHandshakeHdr::ClientHello) continue;

            if (payload_len == tls_record->len() + sizeof(TlsRecordHdr)){

				if (extract_sni(tcp_data, payload_len) == std::string(param.pattern_)) {
					printf("[!] Pattern \"%s\" detected\n", param.pattern_);
					struct LEN_ARGS len_args;
					len_args.ip_len = ipv4_hdr_len;
					len_args.tcp_len = tcp_hdr_len;
					len_args.tcp_data_len = payload_len;
					forwardBlock(pcap, (char*)packet, amac, &len_args);
					backwardBlock(sockfd, (char*)packet, amac, &len_args);
				}
            }
            else{
                printf("[-] Reassembling segmented TLS record\n");
                ParsedData& buf = tls_buffer[key];
                buf.data.append((char*)tcp_data, payload_len);
                buf.total_len = tls_record->len() + sizeof(TlsRecordHdr);
                buf.current_len = payload_len;
            }
        }
        else {
            ParsedData& buf = tls_buffer[key];
            buf.data.append((char*)tcp_data, payload_len);
            buf.current_len += payload_len;
            printf("[-] Successfully reassembled segmented TLS record\n");
            if (extract_sni((uint8_t*)buf.data.data(), buf.current_len) == std::string(param.pattern_)) {
                printf("[!] Pattern \"%s\" detected\n", param.pattern_);
				struct LEN_ARGS len_args;
				len_args.ip_len = ipv4_hdr_len;
				len_args.tcp_len = tcp_hdr_len;
				len_args.tcp_data_len = payload_len;
				forwardBlock(pcap, (char*)packet, amac, &len_args);
				backwardBlock(sockfd, (char*)packet, amac, &len_args);
            }
            tls_buffer.erase(key);
        }
	

	}

	pcap_close(pcap);
}