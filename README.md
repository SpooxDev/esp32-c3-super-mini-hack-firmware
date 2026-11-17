# ESP32-C3 Hack Firmware (c3fw)

Local web UI for WiFi/BLE security auditing on ESP32-C3.

**WARNING:** For isolated lab use and your own devices only.

## Features
| WiFi | BLE |
| :--- | :--- |
| scan / deep scan | passive / active scan |
| deauth | BLE spam |
| beacon / probe flood | proximity spam |
| beacon clone | iBeacon / Airtag |
| sniffer | MAC tracker |

## Build (Arduino IDE)
1. Add URL: `https://espressif.github.io/arduino-esp32/package_esp32_index.json`
2. Board: `ESP32C3 Dev Module` | USB CDC: `Enabled` | Flash: `4MB`
3. Open `c3fw.ino`, upload.

## Usage
1. Connect to WiFi: `c3fw` / `deadbeef`
2. Open: `http://192.168.4.1`
3. Use UI or type `help` in console.

## Limits
- Single radio: WiFi/BLE share antenna (lag possible).
- New SDKs may block raw frame injection (returns 0/N).
