#pragma once

#include <stdint.h>

namespace inspector {

class PcapStreamer;

class SnifferService {
 public:
  void Begin(PcapStreamer* streamer);
  void Poll();
};

}  // namespace inspector
