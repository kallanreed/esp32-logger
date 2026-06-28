#include "framer.h"

#include <Arduino.h>
#include <stdarg.h>
#include <stdio.h>

namespace inspector {

void FramerWrite(uint8_t type, const uint8_t* payload, uint32_t length) {
  Serial.write(kFramerMagic, sizeof(kFramerMagic));
  Serial.write(&type, 1);
  uint8_t length_le[4] = {
      static_cast<uint8_t>(length & 0xFF),
      static_cast<uint8_t>((length >> 8) & 0xFF),
      static_cast<uint8_t>((length >> 16) & 0xFF),
      static_cast<uint8_t>((length >> 24) & 0xFF),
  };
  Serial.write(length_le, sizeof(length_le));
  if (payload != nullptr && length > 0) {
    Serial.write(payload, length);
  }
}

void Log(const char* fmt, ...) {
  char buffer[256];
  va_list args;
  va_start(args, fmt);
  int written = vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  if (written < 0) return;
  uint32_t length = static_cast<uint32_t>(
      written < static_cast<int>(sizeof(buffer)) ? written : sizeof(buffer) - 1);
  FramerWrite(kFrameTypeLog, reinterpret_cast<const uint8_t*>(buffer), length);
}

}  // namespace inspector
