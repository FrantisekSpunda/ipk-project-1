#include <iostream>
#include <bitset>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>

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

  static uint16_t checksum(void *buf, int len)
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

  static void buildPacket(char *packet, const char *src_ip, const char *target_ip, int port)
  {
    struct ip *ip_hdr = (struct ip *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

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

    tcp_hdr->th_sport = htons(12345);
    tcp_hdr->th_dport = htons(port);
    tcp_hdr->th_seq = htonl(0);
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_x2 = 0;
    tcp_hdr->th_off = sizeof(struct tcphdr) / 4;
    tcp_hdr->th_flags = TH_SYN;
    tcp_hdr->th_win = htons(1024);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

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
  }
};

class TcpScanner
{
public:
  static void sendSynPacket(const char *src_ip, const char *target_ip, int port)
  {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
      perror("Socket creation failed");
      exit(1);
    }

    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    PacketBuilder::buildPacket(packet, src_ip, target_ip, port);

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0)
    {
      perror("Failed to send packet");
    }
    else
    {
      std::cout << "TCP SYN packet sent to " << target_ip << ":" << port << std::endl;
    }

    close(sock);
  }

  static void receiveResponse(const char *src_ip, const char *target_ip, int port)
  {
    sendSynPacket(src_ip, target_ip, port);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
      perror("Socket creation failed for listening");
      exit(1);
    }

    char buffer[65536];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    int rst_ack_count = 0;

    for (int i = 0; i < 5; i++)
    {
      ssize_t bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
      if (bytes_received > 0)
      {
        struct ip *ip_hdr = (struct ip *)buffer;
        struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + (ip_hdr->ip_hl * 4));
        std::cout << "Received TCP flags: " << std::bitset<8>(tcp_hdr->th_flags) << std::endl;
        if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        {
          std::cout << "Port is OPEN." << std::endl;
          close(sock);
          return;
        }
        else if ((tcp_hdr->th_flags & (TH_RST | TH_ACK)) == (TH_RST | TH_ACK))
        {
          rst_ack_count++;
          std::cout << "Received RST-ACK (" << rst_ack_count << "/3). Retrying scan..." << std::endl;
          if (rst_ack_count >= 3)
          {
            std::cout << "Port is CLOSED or SYN scan is blocked by firewall." << std::endl;
            close(sock);
            return;
          }
          usleep(100000);
          sendSynPacket(src_ip, target_ip, port);
        }
      }
      usleep(500000);
    }
    std::cout << "Port status UNKNOWN or FILTERED." << std::endl;
    close(sock);
  }
};

int main()
{
  const char *src_ip = "172.18.75.185";
  const char *target_ip = "185.129.138.202";
  int target_port = 443;

  TcpScanner::receiveResponse(src_ip, target_ip, target_port);
  return 0;
}