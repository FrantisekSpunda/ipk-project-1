#include "udp_scanner.hpp"
#include "utils.hpp"

std::string UdpScanner::scanPort(const char *target_ip, int port, int timeout_ms)
{
  bool isIPv6 = Utils::getAddressType(target_ip) == AddressType::IPv6;

  // Create UDP socket
  int udp_sock = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
  if (udp_sock < 0)
  {
    perror("UDP socket failed");
    exit(1);
  }

  //
  if (!isIPv6)
  {
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    // Send UDP socket
    const char *msg = "";
    if (sendto(udp_sock, msg, 0, 0, (sockaddr *)&dest, sizeof(dest)) < 0)
    {
      perror("sendto failed");
      exit(1);
    }
  }
  else
  {
    struct sockaddr_in6 dest6{};
    dest6.sin6_family = AF_INET6;
    dest6.sin6_port = htons(port);
    inet_pton(AF_INET6, target_ip, &dest6.sin6_addr);

    const char *msg = "";
    if (sendto(udp_sock, msg, 0, 0, (sockaddr *)&dest6, sizeof(dest6)) < 0)
    {
      perror("sendto failed");
      exit(1);
    }
  }

  //---------------------------------

  int protocol = IPPROTO_ICMP;

  if (isIPv6)
  {
    protocol = IPPROTO_ICMPV6;
  }

  // Create ICMP socket for response
  int icmp_sock = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_RAW, protocol);
  if (icmp_sock < 0)
  {
    perror("ICMP socket failed");
    exit(1);
  }

  const int max_wait_ms = 1500; // celkový čas čekání 1.5 s
  int waited_ms = 0;

  // Wait for response
  while (waited_ms < max_wait_ms)
  {
    // Wait for ICMP response
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(icmp_sock, &readfds);

    struct timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_ms * 1000;

    int ready = select(icmp_sock + 1, &readfds, nullptr, nullptr, &timeout);

    waited_ms += timeout_ms;

    if (ready > 0)
    {
      char buffer[1024];
      sockaddr_in sender{};
      socklen_t sender_len = sizeof(sender);

      ssize_t len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, (sockaddr *)&sender, &sender_len);
      if (len > 0)
      {
        if (!isIPv6)
        {
          struct ip *ip_hdr = (struct ip *)buffer;
          int ip_hdr_len = ip_hdr->ip_hl * 4;

          struct icmp *icmp_hdr = (struct icmp *)(buffer + ip_hdr_len);

          if (icmp_hdr->icmp_type == 3 && icmp_hdr->icmp_code == 3 && ip_hdr->ip_src.s_addr == inet_addr(target_ip))
          {

            char *icmp_payload = buffer + ip_hdr_len + sizeof(struct icmphdr);

            // Embedded IP header (from the packet we sent)
            struct iphdr *embedded_ip = (struct iphdr *)icmp_payload;
            if (embedded_ip->protocol != IPPROTO_UDP)
              continue;

            int embedded_ip_len = embedded_ip->ihl * 4;
            struct udphdr *embedded_udp = (struct udphdr *)(icmp_payload + embedded_ip_len);

            uint16_t embedded_dest_port = ntohs(embedded_udp->dest);

            if (embedded_dest_port == port)
            {
              close(udp_sock);
              close(icmp_sock);
              return "closed";
            }
          }
        }
        else
        {
          char *icmp6_payload = buffer + sizeof(struct icmp6_hdr);
          struct ip6_hdr *embedded_ip6 = (struct ip6_hdr *)icmp6_payload;
          struct udphdr *embedded_udp = (struct udphdr *)(icmp6_payload + sizeof(struct ip6_hdr));
          struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)buffer;
          struct in6_addr embedded_dest_ip = embedded_ip6->ip6_dst;
          uint16_t embedded_dest_port = ntohs(embedded_udp->dest);
          struct in6_addr target_addr6;
          inet_pton(AF_INET6, target_ip, &target_addr6);

          if (icmp6_hdr->icmp6_type == 1 && icmp6_hdr->icmp6_code == 4)
          {
            if (memcmp(&embedded_dest_ip, &target_addr6, sizeof(struct in6_addr)) == 0 && embedded_dest_port == port)
            {
              close(icmp_sock);
              close(udp_sock);
              return "closed";
            }
          }
        }
      }
    }
  }

  close(udp_sock);
  close(icmp_sock);
  return "open";
}