#include "udp_scanner.hpp"

std::string UdpScanner::scanPort(const char *target_ip, int port, int timeout_ms)
{
  // Create UDP socket
  int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_sock < 0)
  {
    perror("UDP socket failed");
    exit(1);
  }

  //
  struct sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);
  inet_pton(AF_INET, target_ip, &dest.sin_addr);

  // Send UDP socket
  const char *msg = "";
  sendto(udp_sock, msg, 0, 0, (sockaddr *)&dest, sizeof(dest));

  // Create ICMP socket for response
  int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (icmp_sock < 0)
  {
    perror("ICMP socket failed");
    exit(1);
  }

  // Wait for ICMP response
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(icmp_sock, &readfds);
  struct timeval timeout{};
  timeout.tv_sec = 0;
  timeout.tv_usec = timeout_ms * 1000;

  int ready = select(icmp_sock + 1, &readfds, nullptr, nullptr, &timeout);

  if (ready > 0)
  {
    char buffer[1024];
    sockaddr_in sender{};
    socklen_t sender_len = sizeof(sender);

    ssize_t len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, (sockaddr *)&sender, &sender_len);
    if (len > 0)
    {
      struct ip *ip_hdr = (struct ip *)buffer;
      int ip_hdr_len = ip_hdr->ip_hl * 4;

      struct icmp *icmp_hdr = (struct icmp *)(buffer + ip_hdr_len);

      if (icmp_hdr->icmp_type == 3 && icmp_hdr->icmp_code == 3 && ip_hdr->ip_src.s_addr == inet_addr(target_ip))
      {
        close(udp_sock);
        close(icmp_sock);
        return "closed";
      }
    }
  }

  close(udp_sock);
  close(icmp_sock);
  return "open";
}