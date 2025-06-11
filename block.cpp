#include "block.h"

uint16_t checksum(uint16_t *buf, uint8_t len){

	uint32_t sum = 0;
	
	int i;
	for(i=0; i < len; i++){
		sum += ntohs(*buf);
		buf++;
	}
	
	sum = (sum >> 16) + (sum&0xffff);
	sum += (sum >> 16);
	sum ^= 0xffff;
	
	return htons((uint16_t)(sum));

}

void forwardBlock(pcap_t* pcap, char* org_pkt, uint8_t* amac, struct LEN_ARGS* len_args){

	char packet[4096];
	
	memcpy(packet, org_pkt, ETH_LEN + len_args->ip_len + len_args->tcp_len);
	
	
	struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet+ETH_LEN);
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+ETH_LEN + len_args->ip_len);
	
	
	// ETH_HDR
	memcpy(eth_hdr->ether_shost, amac, 6);
	
	// IP_HDR
	ipv4_hdr->ip_len = htons(len_args->ip_len + len_args->tcp_len);
	ipv4_hdr->ip_sum = 0;
	ipv4_hdr->ip_sum = checksum((uint16_t*)ipv4_hdr, len_args->ip_len/2);
	
	// TCP_HDR
	tcp_hdr->th_seq = htonl(ntohl(tcp_hdr->th_seq) + len_args->tcp_data_len);
	tcp_hdr->th_flags = 0;
	tcp_hdr->th_flags |= TH_RST;
	tcp_hdr->th_flags |= TH_ACK;

	struct my_hdr hdr;
	hdr.src = ipv4_hdr->ip_src.s_addr;
	hdr.dst = ipv4_hdr->ip_dst.s_addr;
	hdr.ph = 0;
    	hdr.pro = IPPROTO_TCP;
    	hdr.tcp_len = htons(len_args->tcp_len);
    	
 	tcp_hdr->th_sum = (~checksum((uint16_t*)&hdr, 6));
 	tcp_hdr->th_sum = checksum((uint16_t*)tcp_hdr, len_args->tcp_len/2);
 	
 	
 	int res = pcap_sendpacket(pcap, (u_char*)packet, ETH_LEN + len_args->ip_len + len_args->tcp_len);


}

void backwardBlock(int sockfd, char* org_pkt, uint8_t* amac, struct LEN_ARGS* len_args){

	const char* warn = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr/\r\n\r\n\0";
	char packet[4096];
	
	memcpy(packet, org_pkt+ETH_LEN, len_args->ip_len + len_args->tcp_len);
	memcpy(packet + len_args->ip_len + len_args->tcp_len, warn, strlen(warn));
	
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + len_args->ip_len);
	
	// Socket Setting
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
    	dest_addr.sin_port = tcp_hdr->th_sport;
    	dest_addr.sin_addr.s_addr = ipv4_hdr->ip_src.s_addr;
    	
    	// IP_HDR
    	uint32_t tmp = ipv4_hdr->ip_src.s_addr;
    	ipv4_hdr->ip_src = ipv4_hdr->ip_dst;
    	ipv4_hdr->ip_dst.s_addr = tmp;
    	ipv4_hdr->ip_ttl = 128;
    	ipv4_hdr->ip_len = htons(len_args->tcp_len + len_args->ip_len + strlen(warn));
    	ipv4_hdr->ip_sum = 0;
    	ipv4_hdr->ip_sum = checksum((uint16_t*)ipv4_hdr, len_args->ip_len/2);
    	
    	// TCP_HDR
    	uint32_t ttmp = tcp_hdr->th_ack;
    	tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + len_args->tcp_data_len);
    	tcp_hdr->th_seq = ttmp;
	tcp_hdr->th_flags = 0;
	tcp_hdr->th_flags |= TH_FIN;
	tcp_hdr->th_flags |= TH_ACK;
	tmp = tcp_hdr->th_sport;
	tcp_hdr->th_sport = tcp_hdr->th_dport;
	tcp_hdr->th_dport = tmp;

	struct my_hdr hdr;
	hdr.src = ipv4_hdr->ip_src.s_addr;
	hdr.dst = ipv4_hdr->ip_dst.s_addr;
	hdr.ph = 0;
    	hdr.pro = IPPROTO_TCP;
    	hdr.tcp_len = htons(len_args->tcp_len + strlen(warn));
    	
 	tcp_hdr->th_sum = (~checksum((uint16_t*)&hdr, 6));
 	tcp_hdr->th_sum = checksum((uint16_t*)tcp_hdr, (len_args->tcp_len+strlen(warn))/2);
    	
    				
    	int ret = sendto(sockfd, packet, len_args->tcp_len + len_args->ip_len + strlen(warn), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));


}