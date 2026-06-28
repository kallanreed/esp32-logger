#pragma once

#include <stddef.h>
#include <stdint.h>

struct pbuf;

namespace inspector {

constexpr size_t kPcapMaxFrameBytes = 1518;
constexpr size_t kPcapQueueDepth = 64;

class PcapStreamer {
 public:
  void Begin();
  void Poll();
  void Enqueue(const struct pbuf* p);

  uint32_t dropped_count() const { return dropped_count_; }

 private:
  bool started_ = false;
  uint32_t dropped_count_ = 0;
  uint32_t last_reported_drops_ = 0;
  unsigned long last_drop_log_ms_ = 0;
};

}  // namespace inspector
