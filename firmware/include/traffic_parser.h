#pragma once

#include <array>
#include <stddef.h>
#include <stdint.h>

namespace inspector {

constexpr size_t kMaxCapturedPayloadBytes = 1024;

enum class TransportProtocol : uint8_t {
  kUnknown = 0,
  kTcp,
  kUdp,
};

enum class ApplicationProtocol : uint8_t {
  kUnknown = 0,
  kHttp,
  kMqtt,
  kPlaintext,
};

struct PacketRecord {
  TransportProtocol transport_protocol = TransportProtocol::kUnknown;
  ApplicationProtocol application_protocol = ApplicationProtocol::kUnknown;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  size_t payload_size = 0;
  size_t captured_size = 0;
  bool truncated = false;
  std::array<uint8_t, kMaxCapturedPayloadBytes> payload{};
};

bool Parse80211DataFrame(const uint8_t* frame, size_t frame_len, PacketRecord* out_record);
bool ParseEthernetFrame(const uint8_t* frame, size_t frame_len, PacketRecord* out_record);
bool PayloadLooksLikeText(const uint8_t* payload, size_t payload_len);
void FormatIpv4(uint32_t ip, char* buffer, size_t buffer_len);
const char* ToString(TransportProtocol protocol);
const char* ToString(ApplicationProtocol protocol);

}  // namespace inspector

