#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <semaphore> // C++20 (or use custom counting semaphore)
#include <map>
#include <chrono>

#include "tcp_scanner.hpp"
#include "udp_scanner.hpp"
#include "utils.hpp"

constexpr int MAX_THREADS = 50;
std::counting_semaphore<MAX_THREADS> thread_limiter(MAX_THREADS);
std::mutex result_mutex;

std::map<int, std::string> tcp_results;
std::map<int, std::string> udp_results;

void scanTcpWorker(const std::string &src_ip, const std::string &target_ip, int port, int timeout_ms, const std::string interface)
{
  thread_limiter.acquire();
  int src_port = 40000 + rand() % 20000;
  TcpScanner tcp_scanff(src_ip.c_str(), target_ip.c_str(), interface.c_str(), port, src_port, Utils::getAddressType(src_ip.c_str()) == AddressType::IPv6, timeout_ms);
  std::string result = tcp_scanff.scanPort();

  {
    std::lock_guard<std::mutex> lock(result_mutex);
    tcp_results[port] = result;
  }
  thread_limiter.release();
}

void scanUdpWorker(const std::string &target_ip, int port, int timeout_ms, const std::string interface)
{
  thread_limiter.acquire();
  std::string result = UdpScanner::scanPort(target_ip.c_str(), port, timeout_ms, interface.c_str());

  {
    std::lock_guard<std::mutex> lock(result_mutex);
    udp_results[port] = result;
  }
  thread_limiter.release();
}

int main(int argc, char *argv[])
{
  srand(time(nullptr));

  std::string interface;
  std::vector<int> tcp_ports;
  std::vector<int> udp_ports;
  int timeout_ms = 100;

  static struct option long_options[] = {
      {"interface", required_argument, nullptr, 'i'},
      {"pt", required_argument, nullptr, 't'},
      {"pu", required_argument, nullptr, 'u'},
      {"t", required_argument, nullptr, 't'}, // alias for --pt
      {"u", required_argument, nullptr, 'u'}, // alias for --pu
      {"w", required_argument, nullptr, 'w'},
      {nullptr, 0, nullptr, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "i:t:u:w:", long_options, nullptr)) != -1)
  {
    switch (opt)
    {
    case 'i':
      interface = optarg;
      break;
    case 't':
      tcp_ports = Utils::parsePortRange(optarg);
      break;
    case 'u':
      udp_ports = Utils::parsePortRange(optarg);
      break;
    case 'w':
      timeout_ms = std::stoi(optarg);
      break;
    default:
      std::cerr << "Invalid arguments\n";
      return 1;
    }
  }

  if (optind >= argc)
  {
    std::cerr << "Missing target hostname or IP.\n";
    return 1;
  }

  std::string target = argv[optind];
  std::vector<std::string> ip_list = Utils::resolveDomainToIPs(target);
  std::pair<std::string, std::string> src_ips = Utils::getIPAddressesForInterface(interface);

  std::vector<std::thread> threads;

  for (std::string target_ip : ip_list)
  {
    std::string src_ip = Utils::getAddressType(target_ip) == AddressType::IPv4 ? src_ips.first : src_ips.second;

    for (int port : tcp_ports)
    {
      threads.emplace_back(scanTcpWorker, src_ip, target_ip, port, timeout_ms, interface);
    }
    for (int port : udp_ports)
    {
      threads.emplace_back(scanUdpWorker, target_ip, port, timeout_ms, interface);
    }

    for (auto &t : threads)
    {
      t.join();
    }

    for (const auto &[port, status] : tcp_results)
    {
      std::cout << target_ip << " " << port << " tcp " << status << "\n";
    }

    for (const auto &[port, status] : udp_results)
    {
      std::cout << target_ip << " " << port << " udp " << status << "\n";
    }
  }

  return 0;
}