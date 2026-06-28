#include <stdint.h>
#include <string.h>
#include <unity.h>

#include "traffic_parser.h"

namespace {

using inspector::ApplicationProtocol;
using inspector::PacketRecord;
using inspector::TransportProtocol;

size_t AppendTcpPacket(uint8_t* frame, uint16_t dst_port, const char* payload) {
  memset(frame, 0, 256);

  size_t index = 0;
  frame[index++] = 0x08;
  frame[index++] = 0x01;
  frame[index++] = 0x00;
  frame[index++] = 0x00;

  for (int count = 0; count < 20; ++count) {
    frame[index++] = static_cast<uint8_t>(count + 1);
  }

  frame[index++] = 0xAA;
  frame[index++] = 0xAA;
  frame[index++] = 0x03;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x08;
  frame[index++] = 0x00;

  const size_t payload_len = strlen(payload);
  const uint16_t total_len = static_cast<uint16_t>(20 + 20 + payload_len);

  frame[index++] = 0x45;
  frame[index++] = 0x00;
  frame[index++] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
  frame[index++] = static_cast<uint8_t>(total_len & 0xFF);
  frame[index++] = 0x12;
  frame[index++] = 0x34;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x40;
  frame[index++] = 0x06;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 192;
  frame[index++] = 168;
  frame[index++] = 4;
  frame[index++] = 2;
  frame[index++] = 93;
  frame[index++] = 184;
  frame[index++] = 216;
  frame[index++] = 34;

  frame[index++] = 0xC3;
  frame[index++] = 0x50;
  frame[index++] = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
  frame[index++] = static_cast<uint8_t>(dst_port & 0xFF);
  for (int count = 0; count < 8; ++count) {
    frame[index++] = 0x00;
  }
  frame[index++] = 0x50;
  frame[index++] = 0x18;
  frame[index++] = 0x20;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;

  memcpy(frame + index, payload, payload_len);
  index += payload_len;

  return index;
}

size_t AppendEthernetTcpPacket(uint8_t* frame, uint16_t dst_port, const char* payload) {
  memset(frame, 0, 256);

  size_t index = 0;
  for (int count = 0; count < 6; ++count) frame[index++] = 0x11;
  for (int count = 0; count < 6; ++count) frame[index++] = 0x22;
  frame[index++] = 0x08;
  frame[index++] = 0x00;

  const size_t payload_len = strlen(payload);
  const uint16_t total_len = static_cast<uint16_t>(20 + 20 + payload_len);

  frame[index++] = 0x45;
  frame[index++] = 0x00;
  frame[index++] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
  frame[index++] = static_cast<uint8_t>(total_len & 0xFF);
  frame[index++] = 0x12;
  frame[index++] = 0x34;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x40;
  frame[index++] = 0x06;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 192;
  frame[index++] = 168;
  frame[index++] = 4;
  frame[index++] = 2;
  frame[index++] = 93;
  frame[index++] = 184;
  frame[index++] = 216;
  frame[index++] = 34;

  frame[index++] = 0xC3;
  frame[index++] = 0x50;
  frame[index++] = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
  frame[index++] = static_cast<uint8_t>(dst_port & 0xFF);
  for (int count = 0; count < 8; ++count) frame[index++] = 0x00;
  frame[index++] = 0x50;
  frame[index++] = 0x18;
  frame[index++] = 0x20;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;
  frame[index++] = 0x00;

  memcpy(frame + index, payload, payload_len);
  index += payload_len;
  return index;
}

}  // namespace

void test_parses_http_payload() {
  uint8_t frame[256];
  const char* payload = "GET /status HTTP/1.1\r\nHost: lamp.local\r\n\r\n";
  const size_t frame_len = AppendTcpPacket(frame, 80, payload);

  PacketRecord record;
  const bool parsed = inspector::Parse80211DataFrame(frame, frame_len, &record);

  TEST_ASSERT_TRUE(parsed);
  TEST_ASSERT_EQUAL(TransportProtocol::kTcp, record.transport_protocol);
  TEST_ASSERT_EQUAL(ApplicationProtocol::kHttp, record.application_protocol);
  TEST_ASSERT_EQUAL_UINT16(80, record.dst_port);
  TEST_ASSERT_EQUAL_UINT(strlen(payload), record.payload_size);
  TEST_ASSERT_EQUAL_MEMORY(payload, record.payload.data(), strlen(payload));
}

void test_rejects_encrypted_frame() {
  uint8_t frame[256];
  const size_t frame_len = AppendTcpPacket(frame, 80, "GET / HTTP/1.1\r\n\r\n");
  frame[1] = static_cast<uint8_t>(frame[1] | 0x40);

  PacketRecord record;
  const bool parsed = inspector::Parse80211DataFrame(frame, frame_len, &record);

  TEST_ASSERT_FALSE(parsed);
}

void test_parses_plaintext_non_http_payload() {
  uint8_t frame[256];
  const char* payload = "hello-from-device";
  const size_t frame_len = AppendTcpPacket(frame, 8081, payload);

  PacketRecord record;
  const bool parsed = inspector::Parse80211DataFrame(frame, frame_len, &record);

  TEST_ASSERT_TRUE(parsed);
  TEST_ASSERT_EQUAL(ApplicationProtocol::kPlaintext, record.application_protocol);
}

void test_parses_ethernet_http_payload() {
  uint8_t frame[256];
  const char* payload = "GET /status HTTP/1.1\r\nHost: lamp.local\r\n\r\n";
  const size_t frame_len = AppendEthernetTcpPacket(frame, 80, payload);

  PacketRecord record;
  const bool parsed = inspector::ParseEthernetFrame(frame, frame_len, &record);

  TEST_ASSERT_TRUE(parsed);
  TEST_ASSERT_EQUAL(TransportProtocol::kTcp, record.transport_protocol);
  TEST_ASSERT_EQUAL(ApplicationProtocol::kHttp, record.application_protocol);
  TEST_ASSERT_EQUAL_UINT16(80, record.dst_port);
  TEST_ASSERT_EQUAL_MEMORY(payload, record.payload.data(), strlen(payload));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_parses_http_payload);
  RUN_TEST(test_rejects_encrypted_frame);
  RUN_TEST(test_parses_plaintext_non_http_payload);
  RUN_TEST(test_parses_ethernet_http_payload);
  return UNITY_END();
}
