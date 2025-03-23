#include "packet_builder.hpp"

uint16_t PacketBuilder::checksum(void *buf, int len)
{
  uint16_t *data = (uint16_t *)buf;
  uint32_t sum = 0;
  while (len > 1)
  {
    sum += *data++;
    len -= 2;
  }
  if (len == 1)
  {
    sum += *(uint8_t *)data;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}

void PacketBuilder::buildPacket(char *packet, const char *src_ip, const char *target_ip, int port, int src_port)
{

  // Pointer to IP header
  struct ip *ip_hdr = (struct ip *)packet;

  // Pointer to TCP header which is after IP header
  struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

  // Fill IP header
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
  ip_hdr->ip_id = htons(rand() % 65535);
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = IPPROTO_TCP;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_src.s_addr = inet_addr(src_ip);
  ip_hdr->ip_dst.s_addr = inet_addr(target_ip);

  // Fill TCP header
  tcp_hdr->th_sport = htons(src_port);
  tcp_hdr->th_dport = htons(port);
  tcp_hdr->th_seq = htonl(0);
  tcp_hdr->th_ack = 0;
  tcp_hdr->th_x2 = 0;
  tcp_hdr->th_off = sizeof(struct tcphdr) / 4;
  tcp_hdr->th_flags = TH_SYN;
  tcp_hdr->th_win = htons(1024);
  tcp_hdr->th_sum = 0;
  tcp_hdr->th_urp = 0;

  // PseudoHeader created for checksum
  PseudoHeader pseudo_hdr;
  pseudo_hdr.src_addr = ip_hdr->ip_src.s_addr;
  pseudo_hdr.dest_addr = ip_hdr->ip_dst.s_addr;
  pseudo_hdr.placeholder = 0;
  pseudo_hdr.protocol = IPPROTO_TCP;
  pseudo_hdr.tcp_length = htons(sizeof(struct tcphdr));

  char pseudo_packet[PSEUDO_HEADER_SIZE + sizeof(struct tcphdr)];
  memcpy(pseudo_packet, &pseudo_hdr, PSEUDO_HEADER_SIZE);
  memcpy(pseudo_packet + PSEUDO_HEADER_SIZE, tcp_hdr, sizeof(struct tcphdr));

  tcp_hdr->th_sum = checksum(pseudo_packet, sizeof(pseudo_packet));
  ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));
}