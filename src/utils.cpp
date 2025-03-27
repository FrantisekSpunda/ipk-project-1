#include "utils.hpp"

std::vector<std::string> Utils::resolveDomainToIPs(const std::string &domain)
{
  struct addrinfo hints{}, *res, *p;
  std::vector<std::string> ip_list;

  hints.ai_family = AF_UNSPEC;    // IPv4 i IPv6
  hints.ai_socktype = SOCK_DGRAM; // UDP socket type

  int err = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
  if (err != 0 || res == nullptr)
  {
    std::cerr << "Failed to resolve domain: " << gai_strerror(err) << std::endl;
    exit(1);
  }

  for (p = res; p != nullptr; p = p->ai_next)
  {
    char ip_str[INET6_ADDRSTRLEN] = {0};

    if (p->ai_family == AF_INET)
    {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof(ip_str));
    }
    else if (p->ai_family == AF_INET6)
    {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, sizeof(ip_str));
    }

    if (ip_str[0] != '\0')
    {
      // std::cout << ip_str << "\n";
      ip_list.emplace_back(ip_str);
    }
  }

  freeaddrinfo(res);
  return ip_list;
}

std::pair<std::string, std::string> Utils::getLocalIPAddresses()
{
  struct ifaddrs *ifaddr, *ifa;
  char host[NI_MAXHOST];
  std::string ipv4_addr, ipv6_addr;

  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
  {
    if (ifa->ifa_addr == nullptr)
      continue;

    int family = ifa->ifa_addr->sa_family;

    if (strcmp(ifa->ifa_name, "lo") == 0)
      continue; // Skip loopback

    if (family == AF_INET || family == AF_INET6)
    {
      if (getnameinfo(ifa->ifa_addr,
                      (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                      host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0)
      {
        if (family == AF_INET && ipv4_addr.empty())
        {
          ipv4_addr = std::string(host);
        }
        else if (family == AF_INET6 && ipv6_addr.empty())
        {
          ipv6_addr = std::string(host);
        }

        if (!ipv4_addr.empty() && !ipv6_addr.empty())
          break;
      }
    }
  }

  freeifaddrs(ifaddr);
  return std::make_pair(ipv4_addr, ipv6_addr);
}

std::vector<int> Utils::parsePortRange(const std::string &rangeStr)
{
  std::vector<int> ports;
  std::stringstream ss(rangeStr);
  std::string token;

  while (std::getline(ss, token, ','))
  {
    size_t dash = token.find('-');
    if (dash != std::string::npos)
    {
      int start = std::stoi(token.substr(0, dash));
      int end = std::stoi(token.substr(dash + 1));
      for (int i = start; i <= end; ++i)
        ports.push_back(i);
    }
    else
    {
      ports.push_back(std::stoi(token));
    }
  }

  return ports;
}

std::pair<std::string, std::string> Utils::getIPAddressesForInterface(const std::string &ifaceName)
{
  struct ifaddrs *ifaddr, *ifa;
  char host[NI_MAXHOST];
  std::string ipv4_addr, ipv6_addr;

  if (getifaddrs(&ifaddr) == -1)
  {
    perror("getifaddrs");
    exit(1);
  }

  for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
  {
    if (ifa->ifa_addr == nullptr)
      continue;

    if (!ifaceName.empty() && ifaceName != ifa->ifa_name)
      continue;

    int family = ifa->ifa_addr->sa_family;

    if (family == AF_INET || family == AF_INET6)
    {
      if (getnameinfo(ifa->ifa_addr,
                      (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                      host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0)
      {
        if (family == AF_INET && ipv4_addr.empty())
          ipv4_addr = std::string(host);

        else if (family == AF_INET6 && ipv6_addr.empty())
          ipv6_addr = std::string(host);

        if (!ipv4_addr.empty() && !ipv6_addr.empty())
          break;
      }
    }
  }

  freeifaddrs(ifaddr);

  if (ipv4_addr.empty() && ipv6_addr.empty())
  {
    std::cerr << "Interface " << ifaceName << " has no IP address.\n";
    exit(1);
  }

  return std::make_pair(ipv4_addr, ipv6_addr);
}

AddressType Utils::getAddressType(const std::string &ipStr)
{
  struct in_addr ipv4;
  struct in6_addr ipv6;

  if (inet_pton(AF_INET, ipStr.c_str(), &ipv4) == 1)
    return AddressType::IPv4;

  if (inet_pton(AF_INET6, ipStr.c_str(), &ipv6) == 1)
    return AddressType::IPv6;

  return AddressType::Unknown;
}