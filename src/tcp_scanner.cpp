#include "tcp_scanner.hpp"
#include "packet_builder.hpp"

void TcpScanner::sendSynPacket(int sock, const char *src_ip, const char *target_ip, int port, int src_port)
{
  char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
  PacketBuilder::buildPacket(packet, src_ip, target_ip, port, src_port);

  struct sockaddr_in target;
  target.sin_family = AF_INET;
  target.sin_port = htons(port);
  target.sin_addr.s_addr = inet_addr(target_ip);

  if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0)
  {
    perror("Failed to send packet");
  }
}

void TcpScanner::scanPort(const char *src_ip, const char *target_ip, int port, int src_port)
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

  std::cout << "Scanning port " << port << " on " << target_ip << "..." << std::endl;

  for (int attempt = 1; attempt <= 2; attempt++)
  {

    sendSynPacket(send_sock, src_ip, target_ip, port, src_port);

    const int max_wait_ms = 1500; // celkový čas čekání 1.5 s
    const int slice_ms = 100;     // interval kontroly
    int waited_ms = 0;

    // Wait for response
    while (waited_ms < max_wait_ms)
    {
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(recv_sock, &readfds);

      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = slice_ms * 1000;

      // Read incomming packets
      int ready = select(recv_sock + 1, &readfds, nullptr, nullptr, &timeout);
      waited_ms += slice_ms;
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
            std::cout << "Port " << port << " is OPENED." << std::endl;
            close(send_sock);
            close(recv_sock);
            return;
          }
          else if ((tcp_hdr->th_flags & TH_RST))
          {
            std::cout << "Port " << port << " is CLOSED." << std::endl;
            close(send_sock);
            close(recv_sock);
            return;
          }
        }
      }
    }

    // Pokud nedorazila odpověď – zkusíme to ještě jednou
    usleep(300000);
  }

  std::cout << "Port " << port << " is FILTERED or no response." << std::endl;
  close(send_sock);
  close(recv_sock);
}