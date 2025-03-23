#include <cstdlib>

#include "tcp_scanner.hpp"
#include "udp_scanner.hpp"

int main()
{
  srand(time(nullptr));

  const char *src_ip = "172.22.49.179";
  // const char *target_ip = "185.129.138.202";
  const char *target_ip = "8.8.8.8";
  int target_port = 53;
  int src_port = 40000 + rand() % 20000;

  TcpScanner::scanPort(src_ip, target_ip, target_port, src_port);
  UdpScanner::scanPort(target_ip, target_port);
  return 0;
}