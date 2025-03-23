#ifndef __TCP_SCANNER__
#define __TCP_SCANNER__

#include <iostream>
#include <bitset>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <boost/asio.hpp>

class TcpScanner
{
public:
  static void sendSynPacket(int sock, const char *src_ip, const char *target_ip, int port, int src_port);

  static void scanPort(const char *src_ip, const char *target_ip, int port, int src_port);
};

#endif