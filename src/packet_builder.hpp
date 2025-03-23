#ifndef __PACKET_BUILDER__
#define __PACKET_BUILDER__

#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PSEUDO_HEADER_SIZE 12

class PacketBuilder
{
public:
  struct PseudoHeader
  {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
  };

  static uint16_t checksum(void *buf, int len);
  static void buildPacket(char *packet, const char *src_ip, const char *target_ip, int port, int src_port);
};

#endif