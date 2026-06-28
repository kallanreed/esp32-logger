# esp32-logger Agents Guide

## Scope

This repository is a PlatformIO firmware project for an ESP32 Wi-Fi bridge and traffic inspector.

Primary goals:

- connect upstream as a Wi-Fi station
- expose a SoftAP for IoT devices
- forward client traffic through the ESP32 bridge
- log readable plaintext traffic over serial

## Project Layout

- `firmware/platformio.ini` — PlatformIO environments
- `firmware/sdkconfig.defaults` — ESP-IDF settings required by the bridge build
- `firmware/include/app_config.h` — local Wi-Fi/AP credentials and runtime constants
- `firmware/src/main.cpp` — AP/STA startup and bridge lifecycle
- `firmware/src/sniffer_service.cpp` — promiscuous capture queue and serial logging
- `firmware/src/traffic_parser.cpp` — 802.11/IP/TCP/UDP payload parsing
- `firmware/test/test_traffic_parser/test_main.cpp` — native parser tests

## Build Model

The `esp32dev` firmware environment uses **both** Arduino and ESP-IDF:

- `framework = arduino, espidf`

This is intentional. The bridge depends on lwIP NAPT/IP forwarding, which is enabled from `sdkconfig.defaults`:

- `CONFIG_LWIP_IP_FORWARD=y`
- `CONFIG_LWIP_IPV4_NAPT=y`
- `CONFIG_FREERTOS_HZ=1000`
- `CONFIG_AUTOSTART_ARDUINO=y`

Do not remove the ESP-IDF framework or these settings unless you are replacing the bridge approach entirely.

## Commands

From `firmware/`:

- build: `pio run -e esp32dev`
- flash: `pio run -e esp32dev -t upload --upload-port <port>`
- monitor: `pio device monitor -b 115200 -p <port>`
- parser tests: `pio test -e native`

## Configuration

Edit `firmware/include/app_config.h` before flashing:

- `LOGGER_STA_SSID`
- `LOGGER_STA_PASSWORD`
- `LOGGER_AP_SSID`
- `LOGGER_AP_PASSWORD`

`LOGGER_AP_PASSWORD` may be empty for an open AP. If set, it must be at least 8 characters.

## Implementation Notes

- The firmware should log that STA connectivity separately from bridge forwarding. If upstream Wi-Fi works but NAPT is unavailable, say that explicitly in serial logs.
- Plaintext HTTP and generic readable payloads are currently supported.
- Plaintext WebSocket (`ws://`) decoding is deferred; `wss://` is out of scope because it is encrypted.
- Native tests only cover the parser layer. Keep parser logic testable outside the device runtime.

## Editing Guidance

- Prefer small, local changes; keep parsing logic in `traffic_parser.*` and runtime/device behavior in `main.cpp` or `sniffer_service.cpp`.
- Update `README.md` when changing build, flashing, or credential setup behavior.
- If bridge behavior changes, preserve clear serial diagnostics for AP startup, STA association, DHCP assignment, and forwarding state.
