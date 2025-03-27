#include "tcp_scanner.hpp"
#include "packet_builder.hpp"
#include "utils.hpp"

TcpScanner::TcpScanner(const char *_src_ip, const char *_target_ip, const char *_interface, int _port, int _src_port, bool _isIPv6, int _timeout_ms)
{
  src_ip = _src_ip;
  target_ip = _target_ip;
  port = _port;
  src_port = _src_port;
  isIPv6 = _isIPv6;
  timeout_ms = _timeout_ms;
  interface = _interface;
}

void TcpScanner::sendSynPacket(int sock)
{
  char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
  PacketBuilder::buildPacketIPv4(packet, src_ip, target_ip, port, src_port);

  struct sockaddr_in target;
  target.sin_family = AF_INET;
  target.sin_port = htons(port);
  target.sin_addr.s_addr = inet_addr(target_ip);

  if (interface != "\0")
  {
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, sizeof(interface)) < 0)
    {
      perror("setsockopt SO_BINDTODEVICE failed");
    }
  }

  if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0)
  {
    perror("Failed to send packet");
  }
}

std::string TcpScanner::scanPort()
{
  // Socket pro odeslání SYN packetu
  int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (send_sock < 0)
  {
    perror("Socket (send) creation failed");
    exit(1);
  }

  int one = 1;
  if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
  {
    perror("setsockopt IP_HDRINCL failed");
    exit(1);
  }

  // Socket pro příjem odpovědí
  int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (recv_sock < 0)
  {
    perror("Socket (recv) creation failed");
    exit(1);
  }

  bool isIPv = Utils::getAddressType(src_ip) == AddressType::IPv6;

  for (int attempt = 1; attempt <= 2; attempt++)
  {

    sendSynPacket(send_sock);

    const int max_wait_ms = 1500; // celkový čas čekání 1.5 s
    int waited_ms = 0;

    // Wait for response
    while (waited_ms < max_wait_ms)
    {
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(recv_sock, &readfds);

      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = timeout_ms * 1000;

      // Read incomming packets
      int ready = select(recv_sock + 1, &readfds, nullptr, nullptr, &timeout);
      waited_ms += timeout_ms;
      if (ready > 0)
      {
        char buffer[65536];
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        ssize_t len = recvfrom(recv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
        if (len < 0)
          continue;

        // Get IPs and ports from header
        struct ip *ip_hdr = (struct ip *)buffer;
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + ip_hdr_len);

        // Filter packets we are listening for
        if (ip_hdr->ip_src.s_addr == inet_addr(target_ip) &&
            ntohs(tcp_hdr->th_sport) == port &&
            ntohs(tcp_hdr->th_dport) == src_port)
        {
          if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
          {
            close(send_sock);
            close(recv_sock);
            return "open";
          }
          else if ((tcp_hdr->th_flags & TH_RST))
          {
            close(send_sock);
            close(recv_sock);
            return "closed";
          }
        }
      }
    }
  }

  close(send_sock);
  close(recv_sock);
  return "filtered";
}