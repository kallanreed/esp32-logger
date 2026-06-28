#include "traffic_parser.h"

#include <algorithm>
#include <stdio.h>
#include <string.h>

namespace inspector {
namespace {

constexpr uint16_t kEtherTypeIpv4 = 0x0800;
constexpr uint8_t kIpProtocolTcp = 6;
constexpr uint8_t kIpProtocolUdp = 17;

uint16_t ReadBigEndian16(const uint8_t* data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t ReadBigEndian32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

bool IsPrintablePayloadByte(uint8_t value) {
  return value == '\r' || value == '\n' || value == '\t' || (value >= 32 && value <= 126);
}

bool HasTextPrefix(const uint8_t* payload, size_t payload_len, const char* prefix) {
  const size_t prefix_len = strlen(prefix);
  return payload_len >= prefix_len && memcmp(payload, prefix, prefix_len) == 0;
}

bool LooksLikeHttp(const uint8_t* payload, size_t payload_len) {
  static constexpr const char* kMethods[] = {
      "GET ",
      "POST ",
      "PUT ",
      "PATCH ",
      "DELETE ",
      "HEAD ",
      "OPTIONS ",
      "CONNECT ",
      "TRACE ",
      "HTTP/",
  };
  for (const char* method : kMethods) {
    if (HasTextPrefix(payload, payload_len, method)) {
      return true;
    }
  }
  return false;
}

bool UsesPort(uint16_t lhs, uint16_t rhs, uint16_t target) {
  return lhs == target || rhs == target;
}

ApplicationProtocol DetectApplicationProtocol(
    TransportProtocol transport_protocol,
    uint16_t src_port,
    uint16_t dst_port,
    const uint8_t* payload,
    size_t payload_len) {
  if (transport_protocol == TransportProtocol::kTcp &&
      (UsesPort(src_port, dst_port, 80) ||
       UsesPort(src_port, dst_port, 8000) ||
       UsesPort(src_port, dst_port, 8080) ||
       UsesPort(src_port, dst_port, 8888) ||
       LooksLikeHttp(payload, payload_len))) {
    return ApplicationProtocol::kHttp;
  }

  if (transport_protocol == TransportProtocol::kTcp &&
      (UsesPort(src_port, dst_port, 1883) || UsesPort(src_port, dst_port, 1884))) {
    return ApplicationProtocol::kMqtt;
  }

  if (PayloadLooksLikeText(payload, payload_len)) {
    return ApplicationProtocol::kPlaintext;
  }

  return ApplicationProtocol::kUnknown;
}

bool CopyPayload(
    const uint8_t* payload,
    size_t payload_len,
    PacketRecord* out_record) {
  out_record->payload_size = payload_len;
  out_record->captured_size = std::min(payload_len, kMaxCapturedPayloadBytes);
  out_record->truncated = payload_len > out_record->captured_size;
  if (out_record->captured_size > 0) {
    memcpy(out_record->payload.data(), payload, out_record->captured_size);
  }
  return true;
}

bool ParseTransport(
    const uint8_t* packet,
    size_t packet_len,
    PacketRecord* out_record) {
  if (packet_len < 20) {
    return false;
  }

  const uint8_t version = packet[0] >> 4;
  const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
  if (version != 4 || ip_header_len < 20 || packet_len < ip_header_len) {
    return false;
  }

  const uint16_t total_len = ReadBigEndian16(packet + 2);
  const size_t bounded_total_len = std::min(packet_len, static_cast<size_t>(total_len));
  if (bounded_total_len <= ip_header_len) {
    return false;
  }

  out_record->src_ip = ReadBigEndian32(packet + 12);
  out_record->dst_ip = ReadBigEndian32(packet + 16);

  const uint8_t protocol = packet[9];
  const uint8_t* l4 = packet + ip_header_len;
  const size_t l4_len = bounded_total_len - ip_header_len;

  if (protocol == kIpProtocolTcp) {
    if (l4_len < 20) {
      return false;
    }
    const size_t tcp_header_len = static_cast<size_t>(l4[12] >> 4) * 4;
    if (tcp_header_len < 20 || l4_len < tcp_header_len) {
      return false;
    }
    out_record->transport_protocol = TransportProtocol::kTcp;
    out_record->src_port = ReadBigEndian16(l4);
    out_record->dst_port = ReadBigEndian16(l4 + 2);
    const uint8_t* payload = l4 + tcp_header_len;
    const size_t payload_len = l4_len - tcp_header_len;
    out_record->application_protocol = DetectApplicationProtocol(
        out_record->transport_protocol,
        out_record->src_port,
        out_record->dst_port,
        payload,
        payload_len);
    if (out_record->application_protocol == ApplicationProtocol::kUnknown || payload_len == 0) {
      return false;
    }
    return CopyPayload(payload, payload_len, out_record);
  }

  if (protocol == kIpProtocolUdp) {
    if (l4_len < 8) {
      return false;
    }
    out_record->transport_protocol = TransportProtocol::kUdp;
    out_record->src_port = ReadBigEndian16(l4);
    out_record->dst_port = ReadBigEndian16(l4 + 2);
    const uint8_t* payload = l4 + 8;
    const size_t payload_len = l4_len - 8;
    out_record->application_protocol = DetectApplicationProtocol(
        out_record->transport_protocol,
        out_record->src_port,
        out_record->dst_port,
        payload,
        payload_len);
    if (out_record->application_protocol == ApplicationProtocol::kUnknown || payload_len == 0) {
      return false;
    }
    return CopyPayload(payload, payload_len, out_record);
  }

  return false;
}

}  // namespace

bool Parse80211DataFrame(const uint8_t* frame, size_t frame_len, PacketRecord* out_record) {
  if (frame == nullptr || out_record == nullptr || frame_len < 32) {
    return false;
  }

  *out_record = PacketRecord{};

  const uint16_t frame_control = static_cast<uint16_t>(frame[0] | (frame[1] << 8));
  const uint8_t type = static_cast<uint8_t>((frame_control >> 2) & 0x03);
  const uint8_t subtype = static_cast<uint8_t>((frame_control >> 4) & 0x0F);
  const bool to_ds = (frame_control & 0x0100U) != 0;
  const bool from_ds = (frame_control & 0x0200U) != 0;
  const bool protected_frame = (frame_control & 0x4000U) != 0;
  const bool qos_frame = (subtype & 0x08U) != 0;
  const bool has_ht_control = (frame_control & 0x8000U) != 0;

  if (type != 2 || protected_frame) {
    return false;
  }

  size_t header_len = 24;
  if (to_ds && from_ds) {
    header_len += 6;
  }
  if (qos_frame) {
    header_len += 2;
  }
  if (has_ht_control) {
    header_len += 4;
  }
  if (frame_len < header_len + 8) {
    return false;
  }

  const uint8_t* llc = frame + header_len;
  if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00)) {
    return false;
  }

  const uint16_t ether_type = ReadBigEndian16(llc + 6);
  if (ether_type != kEtherTypeIpv4) {
    return false;
  }

  return ParseTransport(llc + 8, frame_len - header_len - 8, out_record);
}

bool ParseEthernetFrame(const uint8_t* frame, size_t frame_len, PacketRecord* out_record) {
  constexpr size_t kEthernetHeaderLen = 14;
  if (frame == nullptr || out_record == nullptr || frame_len < kEthernetHeaderLen) {
    return false;
  }

  *out_record = PacketRecord{};

  const uint16_t ether_type = ReadBigEndian16(frame + 12);
  if (ether_type != kEtherTypeIpv4) {
    return false;
  }

  return ParseTransport(
      frame + kEthernetHeaderLen,
      frame_len - kEthernetHeaderLen,
      out_record);
}

bool PayloadLooksLikeText(const uint8_t* payload, size_t payload_len) {
  if (payload == nullptr || payload_len == 0) {
    return false;
  }

  size_t printable = 0;
  const size_t sample_len = std::min(payload_len, static_cast<size_t>(128));
  for (size_t index = 0; index < sample_len; ++index) {
    if (IsPrintablePayloadByte(payload[index])) {
      ++printable;
    }
  }

  return printable * 100U >= sample_len * 85U;
}

void FormatIpv4(uint32_t ip, char* buffer, size_t buffer_len) {
  if (buffer == nullptr || buffer_len == 0) {
    return;
  }
  snprintf(
      buffer,
      buffer_len,
      "%u.%u.%u.%u",
      static_cast<unsigned>((ip >> 24) & 0xFFU),
      static_cast<unsigned>((ip >> 16) & 0xFFU),
      static_cast<unsigned>((ip >> 8) & 0xFFU),
      static_cast<unsigned>(ip & 0xFFU));
}

const char* ToString(TransportProtocol protocol) {
  switch (protocol) {
    case TransportProtocol::kTcp:
      return "tcp";
    case TransportProtocol::kUdp:
      return "udp";
    default:
      return "unknown";
  }
}

const char* ToString(ApplicationProtocol protocol) {
  switch (protocol) {
    case ApplicationProtocol::kHttp:
      return "http";
    case ApplicationProtocol::kMqtt:
      return "mqtt";
    case ApplicationProtocol::kPlaintext:
      return "plaintext";
    default:
      return "unknown";
  }
}

}  // namespace inspector

