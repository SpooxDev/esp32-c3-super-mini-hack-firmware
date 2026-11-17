# ESP32-C3 Hack Firmware (c3fw)

Local web UI for WiFi/BLE security auditing on ESP32-C3.

**WARNING:** For isolated lab use and your own devices only.

## Features

### WiFi (Recon & Sniffing)
| Command | Description | Details |
| :--- | :--- | :--- |
| `scan` | Standard scan | Lists SSID, RSSI, Channel, BSSID, Encryption type. |
| `scan_deep` | Deep scan | Same as scan but includes hidden networks (empty SSID). |
| `rssi` | Top 10 | Sorts nearest networks by signal strength (RSSI). |
| `arp` | AP Clients | Lists MAC and RSSI of devices connected to our AP. |
| `fstats` | Frame Stats | Shows count of MGMT, DATA, CTRL frames (if sniffer is on). |
| `sniff` | Sniffer | Toggles promiscuous mode. Counts packets. |
| `framedump` | Frame Dump | Measures traffic for 2 seconds. |
| `promisc` | Promisc | Fast toggle for monitor mode. |

### WiFi (Offensive)
| Command | Description | Details |
| :--- | :--- | :--- |
| `deauth` | Deauth Flood | Sends 15 broadcast deauth frames. |
| `beacon` | Beacon Spam | Sends 5 fake SSIDs (3 loops). |
| `beaconflood` | Beacon Flood | Sends 50 fake SSIDs with random prefixes. |
| `probe` | Probe Spam | Sends 20 probe requests. |
| `probeflood` | Probe Flood | Sends 40 probes per channel (1, 3, 5, 7, 9, 11, 13). |
| `beaconclone` | Clone AP | Clones SSID and BSSID of the strongest nearby network. |
| `authflood` | Auth Flood | Sends 20 authentication frames. |
| `inject` | Inject Test | Tests raw injection (returns 0/N if SDK blocks it). |

### WiFi (Control)
| Command | Description | Details |
| :--- | :--- | :--- |
| `mac` | MAC Random | Randomizes the STA MAC address. |
| `macrestore` | MAC Restore | Restores the factory MAC address. |
| `txpow` | TX Power | Reads current TX power in dBm. |
| `wifioff` | Radio Off | Turns off the WiFi radio entirely. |
| `wifion` | Radio On | Turns the WiFi radio back on (AP mode). |
| `wifireset` | WiFi Reset | Full reset of WiFi settings. |

### BLE (Recon)
| Command | Description | Details |
| :--- | :--- | :--- |
| `blescan` | Passive Scan | Scans BLE devices for 5 seconds. |
| `blescan_deep` | Active Scan | Active scan (requests more data) for 5 seconds. |
| `blelist` | Device List | Outputs the results of the last scan. |
| `blemac` | BLE MAC | Shows the BLE interface MAC address. |
| `bletx` | BLE TX Power | Reads current BLE TX power. |
| `bleexport` | Export CSV | Downloads the last scan as a `.csv` file. |

### BLE (Offensive)
| Command | Description | Details |
| :--- | :--- | :--- |
| `blespam` | BLE Spam | Sends 20 advertising bursts. |
| `bleprox` | Proximity Spam | Sends Apple/Google/MS proximity packets. |
| `blebeacon` | iBeacon | Emulates a fake iBeacon. |
| `bleairtag` | Airtag | Emulates an Apple FindMy (Airtag) packet. |
| `blespoof` | Spoof Name | Spoofs device name (AirPods, Mi Band, etc.). |
| `bletrack_set` | Set Target | Sets the MAC address to track. |
| `bletrack` | Tracker | Searches for the target MAC in the air. |

### BLE (Control)
| Command | Description | Details |
| :--- | :--- | :--- |
| `bleoff` | BLE Off | Stops all BLE scanning and advertising. |
| `blereset` | BLE Reset | Reboots the BLE stack completely. |

### System
| Command | Description | Details |
| :--- | :--- | :--- |
| `info` | System Info | Shows MAC, Flash, CPU, Heap, Uptime. |
| `heap` | Memory | Shows free, min, and max memory. |
| `stats` | Statistics | Shows all counters (packets, attacks, spam). |
| `clr` | Clear | Resets all counters to zero. |
| `reboot` | Reboot | Restarts the ESP32. |
| `help` | Help | Prints all commands to the console. |

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
