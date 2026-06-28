#include "sniffer_service.h"

#include <Arduino.h>
#include <WiFi.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "framer.h"
#include "pcap_streamer.h"

namespace inspector {
namespace {

PcapStreamer* g_streamer = nullptr;
netif_input_fn orig_ap_input = nullptr;
netif_linkoutput_fn orig_ap_linkoutput = nullptr;

err_t ApInputHook(struct pbuf* p, struct netif* inp) {
  if (g_streamer != nullptr) g_streamer->Enqueue(p);
  return orig_ap_input(p, inp);
}

err_t ApLinkOutputHook(struct netif* netif, struct pbuf* p) {
  if (g_streamer != nullptr) g_streamer->Enqueue(p);
  return orig_ap_linkoutput(netif, p);
}

void TryInstallHooks() {
  uint32_t ap_ip = static_cast<uint32_t>(WiFi.softAPIP());
  if (ap_ip == 0) return;
  for (struct netif* n = netif_list; n; n = n->next) {
    if (ip_2_ip4(&n->ip_addr)->addr != ap_ip) continue;
    if (orig_ap_input == nullptr) {
      orig_ap_input = n->input;
      n->input = ApInputHook;
    }
    if (orig_ap_linkoutput == nullptr) {
      orig_ap_linkoutput = n->linkoutput;
      n->linkoutput = ApLinkOutputHook;
    }
    Log("[sniffer] AP capture hooks installed");
    return;
  }
}

}  // namespace

void SnifferService::Begin(PcapStreamer* streamer) {
  g_streamer = streamer;
  TryInstallHooks();
}

void SnifferService::Poll() {
  if (orig_ap_input == nullptr || orig_ap_linkoutput == nullptr) {
    TryInstallHooks();
  }
}

}  // namespace inspector
