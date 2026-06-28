#include "pcap_streamer.h"

#include <Arduino.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <lwip/pbuf.h>
#include <string.h>

#include "framer.h"

namespace inspector {
namespace {

struct PcapRecord {
  uint64_t timestamp_us;
  uint16_t captured_len;
  uint16_t original_len;
  uint8_t  data[kPcapMaxFrameBytes];
};

QueueHandle_t pcap_queue = nullptr;
PcapRecord scratch_record;
uint8_t scratch_pcap_buf[16 + kPcapMaxFrameBytes];

void EmitRecord(const PcapRecord& rec) {
  uint32_t ts_sec = static_cast<uint32_t>(rec.timestamp_us / 1000000ULL);
  uint32_t ts_usec = static_cast<uint32_t>(rec.timestamp_us % 1000000ULL);
  uint32_t cap_len = rec.captured_len;
  uint32_t orig_len = rec.original_len;
  memcpy(scratch_pcap_buf + 0, &ts_sec, 4);
  memcpy(scratch_pcap_buf + 4, &ts_usec, 4);
  memcpy(scratch_pcap_buf + 8, &cap_len, 4);
  memcpy(scratch_pcap_buf + 12, &orig_len, 4);
  memcpy(scratch_pcap_buf + 16, rec.data, rec.captured_len);
  FramerWrite(kFrameTypePcap, scratch_pcap_buf, 16 + rec.captured_len);
}

}  // namespace

void PcapStreamer::Begin() {
  if (started_) return;
  if (pcap_queue == nullptr) {
    pcap_queue = xQueueCreate(kPcapQueueDepth, sizeof(PcapRecord));
    if (pcap_queue == nullptr) {
      Log("[pcap] failed to allocate queue");
      return;
    }
  }
  started_ = true;
  Log("[pcap] streaming ready (queue=%u recs of %u bytes)",
      static_cast<unsigned>(kPcapQueueDepth),
      static_cast<unsigned>(sizeof(PcapRecord)));
}

void PcapStreamer::Enqueue(const struct pbuf* p) {
  if (!started_ || pcap_queue == nullptr || p == nullptr || p->tot_len == 0) {
    return;
  }
  PcapRecord rec;
  rec.timestamp_us = static_cast<uint64_t>(esp_timer_get_time());
  rec.original_len = p->tot_len;
  // pbuf_copy_partial walks the chain and copies up to buffer size.
  uint16_t copied = pbuf_copy_partial(
      const_cast<struct pbuf*>(p), rec.data, sizeof(rec.data), 0);
  rec.captured_len = copied;
  if (copied == 0) return;

  // Brief wait when full so we backpressure rather than drop on transient bursts.
  if (xQueueSend(pcap_queue, &rec, pdMS_TO_TICKS(20)) != pdPASS) {
    ++dropped_count_;
  }
}

void PcapStreamer::Poll() {
  if (!started_ || pcap_queue == nullptr) return;

  while (xQueueReceive(pcap_queue, &scratch_record, 0) == pdPASS) {
    EmitRecord(scratch_record);
  }

  if (dropped_count_ > last_reported_drops_) {
    unsigned long now = millis();
    if (now - last_drop_log_ms_ >= 5000UL) {
      Log("[pcap] dropped %u records (total)", dropped_count_);
      last_reported_drops_ = dropped_count_;
      last_drop_log_ms_ = now;
    }
  }
}

}  // namespace inspector
