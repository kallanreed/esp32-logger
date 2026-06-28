# esp32-logger

ESP32-WROOM firmware that stands up an isolated SoftAP for IoT devices, NATs them through an upstream Wi-Fi network, and streams **every Ethernet frame** to/from connected clients as a standard pcap stream over UART.

## What it does

- Connects the ESP32 to your upstream Wi-Fi network (STA mode).
- Exposes a WPA2-secured SoftAP for IoT devices.
- Enables NAPT so AP clients can reach the upstream network through the ESP32.
- Sets the DHCP server to advertise a working public DNS resolver (1.1.1.1 by default) so clients don't get stuck on the gateway's address.
- Captures the full Ethernet frame of every packet entering or leaving the AP interface and streams it host-side as classic pcap, ready for Wireshark/tshark/scapy.

## Capture details

- Capture happens at the IP layer after NAPT, so client IPs are visible in both directions. 802.11 management frames are not captured.
- Only the AP interface is mirrored. Upstream-side broadcasts on the STA network are not included.
- HTTPS/TLS payload is not decrypted — you see ciphertext.

## Configure credentials

Edit `firmware/include/app_config.h` before flashing:

- `LOGGER_STA_SSID`, `LOGGER_STA_PASSWORD` — upstream Wi-Fi the ESP32 joins
- `LOGGER_AP_SSID`, `LOGGER_AP_PASSWORD` — SoftAP the IoT device connects to

Leave `LOGGER_AP_PASSWORD` empty for an open AP, or set it to ≥ 8 chars for WPA2 (most IoT clients require WPA2).

## Build and flash

```bash
cd firmware
pio run -e esp32dev
pio run -e esp32dev -t upload
```

The firmware runs the UART at **921600 baud**.

## Capture traffic

Run the host capture script in a terminal (close any open `pio device monitor` first — only one process can hold the serial port):

```bash
python3 tools/capture.py -o capture.pcap
```

The script reads the framed UART stream and writes a standard `.pcap` file. Log lines from the device print to stderr prefixed with `[esp]`.

Open in Wireshark:

```bash
wireshark capture.pcap
```

Or feed Wireshark live via a FIFO:

```bash
mkfifo /tmp/esp.pcap
python3 tools/capture.py -o /tmp/esp.pcap &
wireshark -k -i /tmp/esp.pcap
```

Or pipe to tshark for command-line dissection:

```bash
python3 tools/capture.py -o - | tshark -r - -V
```

Override the serial port if needed:

```bash
python3 tools/capture.py --port /dev/cu.usbserial-0001 -o capture.pcap
```

`pyserial` is the only Python dependency: `pip install pyserial`.

## Architecture

The UART carries a simple framed multiplex so log text and pcap bytes coexist on one channel:

```
[4-byte magic 0xE5 0xC0 0x32 0x70][1-byte type][4-byte length, little-endian][payload]
```

- Type `0x01` — log text (boot info, NAPT state, client connect/disconnect, drop reports)
- Type `0x02` — pcap bytes (the classic pcap global header is emitted once at startup, then every captured frame becomes a pcap record)

On the device, capture hooks installed at the lwIP AP-netif level enqueue raw Ethernet frames (after WPA2 decryption, with chained pbufs walked via `pbuf_copy_partial`) into a 64-record MTU-sized queue. Records are drained from the main loop and written through the framer. Enqueue waits briefly when the queue is full, so transient bursts apply natural backpressure instead of dropping. If a drop does happen, the count is logged via the framed log channel every 5 s.

## Run unit tests

```bash
cd firmware
pio test -e native
```

## Other tools

- `tools/capture.py` — host-side UART → pcap demux (see above).
