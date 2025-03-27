#ifndef __UTILS__
#define __UTILS__

#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <ifaddrs.h>
#include <string.h>
#include <vector>
#include <sstream>
#include <getopt.h>
#include <iostream>

#define BUFFER_SIZE 1024

enum class AddressType
{
  IPv4,
  IPv6,
  Unknown
};

class Utils
{
public:
  static std::vector<std::string> resolveDomainToIPs(const std::string &domain);
  static std::pair<std::string, std::string> getLocalIPAddresses();
  static std::vector<int> parsePortRange(const std::string &rangeStr);
  static std::pair<std::string, std::string> getIPAddressesForInterface(const std::string &ifaceName);
  static AddressType getAddressType(const std::string &ipStr);
};

#endif