#include <Arduino.h>
#include <WiFi.h>
#include <dhcpserver/dhcpserver.h>
#include <esp_netif.h>
#include <lwip/opt.h>
#if IP_FORWARD && IP_NAPT
#include <lwip/lwip_napt.h>
#endif

#include "app_config.h"
#include "framer.h"
#include "pcap_streamer.h"
#include "sniffer_service.h"

#ifndef PIO_UNIT_TESTING

namespace {

inspector::PcapStreamer pcap_streamer;
inspector::SnifferService sniffer;

const char* GetApPassphrase() {
  return inspector::config::kApPassword[0] == '\0' ? nullptr : inspector::config::kApPassword;
}

bool HasValidApPassphrase() {
  const char* passphrase = GetApPassphrase();
  return passphrase == nullptr || strlen(passphrase) >= 8;
}

bool SetApDhcpDns(IPAddress dns) {
  esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!ap_netif) return false;
  if (esp_netif_dhcps_stop(ap_netif) != ESP_OK) return false;

  dhcps_offer_t offer_dns = OFFER_DNS;
  if (esp_netif_dhcps_option(
          ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
          &offer_dns, sizeof(offer_dns)) != ESP_OK) {
    return false;
  }

  esp_netif_dns_info_t dns_info{};
  dns_info.ip.type = ESP_IPADDR_TYPE_V4;
  dns_info.ip.u_addr.ip4.addr = static_cast<uint32_t>(dns);
  if (esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_info) != ESP_OK) {
    return false;
  }

  return esp_netif_dhcps_start(ap_netif) == ESP_OK;
}

bool SetApNaptEnabled(bool enabled) {
#if IP_FORWARD && IP_NAPT
  esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!ap_netif) return false;
  // esp_netif_get_netif_impl_index returns netif->num+1; ip_napt_enable_no matches on netif->num.
  int netif_num = esp_netif_get_netif_impl_index(ap_netif) - 1;
  ip_napt_enable_no(static_cast<uint8_t>(netif_num), enabled ? 1 : 0);
  return true;
#else
  (void)enabled;
  return false;
#endif
}

void HandleNetworkEvent(arduino_event_id_t event, arduino_event_info_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      inspector::Log("[wifi] upstream connected");
      break;

    case ARDUINO_EVENT_WIFI_STA_GOT_IP: {
      char ip[16], gw[16];
      IPAddress(info.got_ip.ip_info.ip.addr).toString().toCharArray(ip, sizeof(ip));
      IPAddress(info.got_ip.ip_info.gw.addr).toString().toCharArray(gw, sizeof(gw));
      inspector::Log("[wifi] upstream ip=%s gw=%s", ip, gw);
      if (SetApNaptEnabled(true)) {
        inspector::Log("[wifi] NAPT enabled");
      } else {
        inspector::Log("[wifi] NAPT unavailable");
      }
      sniffer.Begin(&pcap_streamer);
      break;
    }

    case ARDUINO_EVENT_WIFI_STA_LOST_IP:
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      SetApNaptEnabled(false);
      inspector::Log("[wifi] upstream lost");
      break;

    case ARDUINO_EVENT_WIFI_AP_START: {
      char ip[16];
      WiFi.softAPIP().toString().toCharArray(ip, sizeof(ip));
      inspector::Log("[ap] started ssid=%s ip=%s", inspector::config::kApSsid, ip);
      break;
    }

    case ARDUINO_EVENT_WIFI_AP_STACONNECTED: {
      const auto& mac = info.wifi_ap_staconnected.mac;
      inspector::Log("[ap] client connected mac=%02X:%02X:%02X:%02X:%02X:%02X aid=%u",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
          info.wifi_ap_staconnected.aid);
      break;
    }

    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED: {
      const auto& mac = info.wifi_ap_stadisconnected.mac;
      inspector::Log("[ap] client disconnected mac=%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      break;
    }

    case ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED: {
      char ip[16];
      IPAddress(info.wifi_ap_staipassigned.ip.addr).toString().toCharArray(ip, sizeof(ip));
      inspector::Log("[ap] client ip=%s", ip);
      break;
    }

    default:
      break;
  }
}

}  // namespace

void setup() {
  Serial.setTxBufferSize(inspector::config::kSerialTxBufferBytes);
  Serial.begin(inspector::config::kMonitorBaudRate);
  delay(200);

  inspector::Log("esp32-logger booting sta-ssid=%s ap-ssid=%s ap-security=%s",
      inspector::config::kStaSsid,
      inspector::config::kApSsid,
      GetApPassphrase() == nullptr ? "open" : "wpa2");

  WiFi.onEvent(HandleNetworkEvent);
  WiFi.setSleep(false);
  WiFi.mode(WIFI_MODE_APSTA);

  if (!HasValidApPassphrase()) {
    inspector::Log("[ap] password must be 8+ chars or empty for open AP");
    return;
  }

  IPAddress apIp(
      inspector::config::kApIp0, inspector::config::kApIp1,
      inspector::config::kApIp2, inspector::config::kApIp3);
  IPAddress apMask(
      inspector::config::kApMask0, inspector::config::kApMask1,
      inspector::config::kApMask2, inspector::config::kApMask3);
  IPAddress apLeaseStart(
      inspector::config::kApLease0, inspector::config::kApLease1,
      inspector::config::kApLease2, inspector::config::kApLease3);
  IPAddress apDns(
      inspector::config::kApDns0, inspector::config::kApDns1,
      inspector::config::kApDns2, inspector::config::kApDns3);

  if (!WiFi.softAPConfig(apIp, apIp, apMask, apLeaseStart)) {
    inspector::Log("[ap] failed to configure AP interface");
    return;
  }

  if (!WiFi.softAP(
          inspector::config::kApSsid,
          GetApPassphrase(),
          inspector::config::kApChannel,
          0,
          inspector::config::kApMaxClients)) {
    inspector::Log("[ap] failed to create AP");
    return;
  }

  if (SetApDhcpDns(apDns)) {
    char ip[16];
    apDns.toString().toCharArray(ip, sizeof(ip));
    inspector::Log("[ap] DHCP DNS set to %s", ip);
  } else {
    inspector::Log("[ap] failed to set DHCP DNS");
  }

  pcap_streamer.Begin();

  WiFi.begin(inspector::config::kStaSsid, inspector::config::kStaPassword);
}

void loop() {
  sniffer.Poll();
  pcap_streamer.Poll();
  delay(1);
}

#endif
