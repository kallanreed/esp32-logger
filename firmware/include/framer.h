#pragma once

#include <stddef.h>
#include <stdint.h>

namespace inspector {

// UART framing protocol used to multiplex log text and pcap bytes on a single
// serial stream. Each frame on the wire is:
//   [4-byte magic][1-byte type][4-byte length, little-endian][payload bytes]
// The host-side capture script synchronises on the magic and dispatches by
// type. Types other than the ones below are reserved.
constexpr uint8_t kFramerMagic[4] = {0xE5, 0xC0, 0x32, 0x70};
constexpr uint8_t kFrameTypeLog = 0x01;
constexpr uint8_t kFrameTypePcap = 0x02;

// Writes a single framed record to Serial. Safe to call from the main task.
// Not safe to call concurrently from multiple tasks — callers serialise.
void FramerWrite(uint8_t type, const uint8_t* payload, uint32_t length);

// Convenience: format a log line and emit it as a kFrameTypeLog record.
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace inspector
