#pragma once

#include <stdint.h>

#ifndef LOGGER_MONITOR_BAUD
#define LOGGER_MONITOR_BAUD 921600
#endif

#ifndef LOGGER_SERIAL_TX_BUFFER
#define LOGGER_SERIAL_TX_BUFFER 32768
#endif

#ifndef LOGGER_STA_SSID
#define LOGGER_STA_SSID "TODO"
#endif

#ifndef LOGGER_STA_PASSWORD
#define LOGGER_STA_PASSWORD "TODO"
#endif

#ifndef LOGGER_AP_SSID
#define LOGGER_AP_SSID "iot-debug-open"
#endif

#ifndef LOGGER_AP_PASSWORD
#define LOGGER_AP_PASSWORD "iot-debug-1234"
#endif

namespace inspector::config {

constexpr uint32_t kMonitorBaudRate = LOGGER_MONITOR_BAUD;
constexpr char kStaSsid[] = LOGGER_STA_SSID;
constexpr char kStaPassword[] = LOGGER_STA_PASSWORD;
constexpr char kApSsid[] = LOGGER_AP_SSID;
constexpr char kApPassword[] = LOGGER_AP_PASSWORD;
constexpr uint8_t kApIp0 = 192;
constexpr uint8_t kApIp1 = 168;
constexpr uint8_t kApIp2 = 4;
constexpr uint8_t kApIp3 = 1;
constexpr uint8_t kApMask0 = 255;
constexpr uint8_t kApMask1 = 255;
constexpr uint8_t kApMask2 = 255;
constexpr uint8_t kApMask3 = 0;
constexpr uint8_t kApLease0 = 192;
constexpr uint8_t kApLease1 = 168;
constexpr uint8_t kApLease2 = 4;
constexpr uint8_t kApLease3 = 2;
constexpr uint8_t kApDns0 = 1;
constexpr uint8_t kApDns1 = 1;
constexpr uint8_t kApDns2 = 1;
constexpr uint8_t kApDns3 = 1;
constexpr uint8_t kApChannel = 1;
constexpr uint8_t kApMaxClients = 4;
constexpr size_t kSerialTxBufferBytes = LOGGER_SERIAL_TX_BUFFER;

}  // namespace inspector::config
