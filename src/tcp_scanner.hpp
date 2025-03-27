#ifndef __TCP_SCANNER__
#define __TCP_SCANNER__

#include <iostream>
#include <bitset>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>

class TcpScanner
{
private:
  const char *src_ip;
  const char *target_ip;
  const char *interface;
  int port;
  int src_port;
  bool isIPv6;
  int timeout_ms;

public:
  TcpScanner(const char *_src_ip, const char *_target_ip, const char *_interface, int _port, int _src_port, bool _isIPv6, int _timeout_ms);
  void sendSynPacket(int sock);
  std::string scanPort();
};

#endif