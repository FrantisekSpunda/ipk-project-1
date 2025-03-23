#ifndef __UDP_SCANNER__
#define __UDP_SCANNER__

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

class UdpScanner
{
public:
  static void scanPort(const char *target_ip, int port);
};

#endif