/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  ESP32 NODE 1 — Web Gateway & Security Suite UI             ║
 * ║  ─────────────────────────────────────────────────────────  ║
 * ║  • Hosts Wi-Fi AP "ESP32-PenTool" on 192.168.4.1            ║
 * ║  • Serves full tabbed Security Suite UI (port 80)           ║
 * ║  • WebSocket server (port 81) for real-time terminal        ║
 * ║  • Forwards all browser commands → ESP2 via ESP-NOW         ║
 * ║  • Receives all results from ESP2 → pushes to browser       ║
 * ║                                                              ║
 * ║  SETUP: Flash ESP2 first, copy its STA MAC printed on       ║
 * ║         Serial, paste into ESP2_MAC[] below, then flash.    ║
 * ║                                                              ║
 * ║  Libraries required (Arduino IDE Library Manager):          ║
 * ║    • WebSockets by Markus Sattler (≥ 2.4.1)                 ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

#include <WiFi.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <esp_now.h>
#include <esp_wifi.h>

// ─────────────────────────────────────────────
//  ★ CONFIGURE: paste ESP2's STA MAC here
//    (printed on ESP2 Serial Monitor at boot)
// ─────────────────────────────────────────────
uint8_t ESP2_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // ← CHANGE THIS TO YOUR NODE 2 MAC

// AP credentials (users connect here to access the tool)
const char* AP_SSID = "ESP32-PenTool";
const char* AP_PASS = "pentest1";   // min 8 chars for WPA2

// ─────────────────────────────────────────────
//  Server objects
// ─────────────────────────────────────────────
WebServer        httpServer(80);
WebSocketsServer wsServer(81);

// ─────────────────────────────────────────────
//  ISR-safe message queue  (ESP-NOW → WebSocket)
//  Each slot holds up to MSG_LEN bytes.
// ─────────────────────────────────────────────
#define QUEUE_SIZE 32
#define MSG_LEN    252
static char          msgQueue[QUEUE_SIZE][MSG_LEN];
static volatile int  qHead = 0, qTail = 0;
static volatile bool queueOverflow = false;

// ─────────────────────────────────────────────
//  ESP-NOW peer handle
// ─────────────────────────────────────────────
esp_now_peer_info_t peerInfo;

// ─────────────────────────────────────────────
//  Heartbeat / link-status
// ─────────────────────────────────────────────
static unsigned long lastHeartbeat    = 0;
static unsigned long lastPongTime     = 0;
static bool          node2Online      = false;
#define HEARTBEAT_MS   3000   // send ping every 3s
#define PONG_TIMEOUT   8000   // mark offline if no reply for 8s

// ─────────────────────────────────────────────
//  Connected WebSocket client (only one at a time)
// ─────────────────────────────────────────────
static int8_t activeClient = -1;

// ═════════════════════════════════════════════════════════════════
//  HTML — Full Tabbed Security Suite UI
// ═════════════════════════════════════════════════════════════════
const char HTML_PAGE[] = R"rawliteral(
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>ESP32 Pen-Tool</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
:root{--bg:#050a05;--surf:#0a110a;--brd:#1a2f1a;--green:#00ff41;--cyan:#0ff;--yellow:#ffb700;--red:#ff003c;--purple:#b0f;--orange:#ff7300;--muted:#4a6b4a;--text:#c8e8c8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;display:flex;flex-direction:column;height:100vh;overflow:hidden}
.scanlines{position:fixed;top:0;left:0;width:100vw;height:100vh;background:linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.25) 50%), linear-gradient(90deg, rgba(255,0,0,0.06), rgba(0,255,0,0.02), rgba(0,0,255,0.06));background-size:100% 4px, 6px 100%;pointer-events:none;z-index:9999}
header{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;background:var(--surf);border-bottom:2px solid var(--brd);flex-shrink:0;box-shadow:0 0 10px rgba(0,255,65,0.1)}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.1rem;color:var(--green);text-shadow:0 0 5px var(--green);animation:glitch 3s infinite}
@keyframes glitch{0%,100%{text-shadow:0 0 5px var(--green)}2%{text-shadow:2px 0 0 var(--red), -2px 0 0 var(--cyan)}4%{text-shadow:0 0 5px var(--green)}}
.li{width:28px;height:28px;background:var(--green);color:black;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold}
.hr{display:flex;align-items:center;gap:10px;font-size:.75rem;color:var(--muted)}
.wsd{width:8px;height:8px;background:var(--red);display:inline-block;margin-right:4px;transition:background .3s}
.wsd.on{background:var(--green);animation:pulse 2s infinite;box-shadow:0 0 8px var(--green)}
.wsd.warn{background:var(--yellow);box-shadow:0 0 8px var(--yellow)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.badge{padding:3px 8px;font-size:.7rem;font-weight:bold;border:1px solid var(--brd);background:black;color:var(--muted);text-transform:uppercase}
.badge.on{background:rgba(0,255,65,.1);color:var(--green);border-color:var(--green);box-shadow:0 0 8px rgba(0,255,65,.3)}
.badge.warn{background:rgba(255,183,0,.1);color:var(--yellow);border-color:var(--yellow);box-shadow:0 0 8px rgba(255,183,0,.3)}
.tabs{display:flex;gap:0;padding:8px 12px 0;background:var(--surf);border-bottom:1px solid var(--brd);overflow-x:auto;flex-shrink:0}
.tabs::-webkit-scrollbar{height:3px}.tabs::-webkit-scrollbar-thumb{background:var(--green)}
.tb{padding:8px 16px;border:1px solid var(--brd);border-bottom:none;background:black;color:var(--muted);font-size:.75rem;font-family:inherit;cursor:pointer;white-space:nowrap;transition:all .2s;text-transform:uppercase}
.tb:hover{background:var(--brd);color:var(--text);box-shadow:inset 0 -2px 0 var(--green)}
.tb.act{background:rgba(0,255,65,.05);color:var(--green);border-color:var(--green);border-bottom-color:black;box-shadow:inset 0 2px 0 var(--green)}
.panels{flex-shrink:0}
.panel{display:none;padding:12px 18px;background:linear-gradient(180deg, var(--surf) 0%, black 100%);border-bottom:1px solid var(--brd);animation:fade 0.3s}
.panel.act{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
@keyframes fade{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:none}}
.lbl{font-size:.75rem;color:var(--muted);white-space:nowrap}
.inp{padding:6px 10px;background:black;border:1px solid var(--brd);color:var(--green);font-size:.75rem;font-family:inherit;transition:.2s}
.inp:focus{outline:none;border-color:var(--green);box-shadow:0 0 5px rgba(0,255,65,.3)}
.btn{padding:6px 14px;border:1px solid var(--brd);background:black;color:var(--text);font-size:.75rem;font-family:inherit;cursor:pointer;transition:all .2s;white-space:nowrap;text-transform:uppercase;font-weight:bold}
.btn:hover{background:var(--brd);color:var(--green);border-color:var(--green);box-shadow:0 0 8px rgba(0,255,65,.3)}
.btn.g:hover{background:var(--green);color:black}
.btn.r:hover{background:var(--red);color:black;border-color:var(--red);box-shadow:0 0 8px var(--red)}
.btn.b:hover{background:var(--cyan);color:black;border-color:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.btn.o:hover{background:var(--orange);color:black;border-color:var(--orange);box-shadow:0 0 8px var(--orange)}
.btn.pu:hover{background:var(--purple);color:black;border-color:var(--purple);box-shadow:0 0 8px var(--purple)}
.btn.y:hover{background:var(--yellow);color:black;border-color:var(--yellow);box-shadow:0 0 8px var(--yellow)}
.sep{width:1px;height:20px;background:var(--brd);flex-shrink:0}
#terminal{flex:1;overflow-y:auto;padding:15px 20px;font-size:.85rem;line-height:1.6;background:black;text-shadow:0 0 2px rgba(0,255,65,.4)}
#terminal::-webkit-scrollbar{width:5px}#terminal::-webkit-scrollbar-thumb{background:var(--brd)}
.ln{display:block;animation:fi .1s;white-space:pre-wrap;word-break:break-all}
@keyframes fi{from{opacity:0;transform:translateY(2px)}to{opacity:1;transform:none}}
.sys{color:var(--cyan)}.inp-ln{color:var(--yellow)}.out{color:var(--green)}.err{color:var(--red)}.info{color:var(--muted)}.scan{color:var(--orange)}.hs{color:var(--purple)}.evil{color:var(--red)}
.node2-dot{width:8px;height:8px;background:var(--red);display:inline-block;margin-right:4px;transition:background .3s}
.node2-dot.on{background:var(--green);animation:pulse 2s infinite;box-shadow:0 0 8px var(--green)}
</style></head><body>
<div class="scanlines"></div>
<div style="display:flex;height:100vh;width:100vw;overflow:hidden;">
  <div id="wolf-sidebar" style="width:280px;background:black;border-right:1px solid var(--brd);display:flex;align-items:center;justify-content:center;color:var(--green);font-size:10px;line-height:10px;white-space:pre;text-shadow:0 0 5px var(--green);flex-shrink:0;user-select:none;"></div>
  <div style="flex:1;display:flex;flex-direction:column;overflow:hidden">
<header>
  <div class="logo"><div class="li" style="flex-direction:column;font-size:5px;line-height:5px;width:34px;height:34px;background:none;border:1px solid var(--green);color:var(--green);box-shadow:inset 0 0 5px var(--green);padding-top:2px;letter-spacing:1px;">&nbsp;&nbsp;10<br>&nbsp;110<br>1100<br>&nbsp;&nbsp;01</div>ESP32 PEN-TOOL</div>
  <div class="hr">
    <span><span class="wsd" id="wsDot"></span><span id="wsLbl">Disconnected</span></span>
    <span><span class="node2-dot" id="n2Dot"></span><span id="n2Lbl">Node2:?</span></span>
    <span class="badge" id="monBadge">MON:OFF</span>
    <span class="badge" id="deauthBadge">DEAUTH:OFF</span>
    <span class="badge" id="evilBadge">EVIL:OFF</span>
  </div>
</header>

<div class="tabs">
  <button class="tb act" onclick="tab('monitor',this)">&#x1F4E1; Monitor</button>
  <button class="tb" onclick="tab('deauth',this)">&#x26A1; Deauth</button>
  <button class="tb" onclick="tab('beacon',this)">&#x1F4F6; Beacon</button>
  <button class="tb" onclick="tab('evil',this)">&#x1F608; Evil Twin</button>
  <button class="tb" onclick="tab('hs',this)">&#x1F91D; Handshake</button>
  <button class="tb" onclick="tab('ps',this)">&#x1F50D; Port Scan</button>
  <button class="tb" onclick="tab('wd',this)">&#x1F5FA; Wardrive</button>
  <button class="tb" onclick="tab('crack',this)">&#x1F513; WPA2 Crack</button>
</div>

<div class="panels">
  <div class="panel act" id="p-monitor">
    <button class="btn g" onclick="send('monitor start')">&#x25B6; Start Monitor</button>
    <button class="btn r" onclick="send('monitor stop')">&#x25A0; Stop Monitor</button>
    <div class="sep"></div>
    <span class="lbl">Ch:</span>
    <select class="inp" id="monCh" style="width:60px">
      <option>1</option><option>2</option><option>3</option><option>4</option><option>5</option>
      <option selected>6</option><option>7</option><option>8</option><option>9</option>
      <option>10</option><option>11</option><option>12</option><option>13</option>
    </select>
    <button class="btn b" onclick="send('channel '+v('monCh'))">Set Ch</button>
    <div class="sep"></div>
    <button class="btn" onclick="runScan()">&#x1F501; Scan APs</button>
    <button class="btn" onclick="send('status')">&#x2139; Status</button>
    <button class="btn" onclick="clearTerm()">&#x1F5D1; Clear</button>
  </div>

  <div class="panel" id="p-deauth">
    <button class="btn b" onclick="runScan()">&#x1F501; Scan</button>
    <select class="inp" id="apD" style="width:230px"><option value="">-- select AP --</option></select>
    <span class="lbl">Client:</span>
    <input class="inp" id="dCli" placeholder="FF:FF:FF:FF:FF:FF (all)" style="width:160px">
    <div class="sep"></div>
    <button class="btn g" onclick="startDeauth()">&#x26A1; Start Deauth</button>
    <button class="btn r" onclick="send('deauth stop')">&#x25A0; Stop</button>
  </div>

  <div class="panel" id="p-beacon">
    <button class="btn g" onclick="send('beacon start')">&#x25B6; Start Beacon Spam</button>
    <button class="btn r" onclick="send('beacon stop')">&#x25A0; Stop</button>
    <div class="sep"></div>
    <span class="lbl" style="color:var(--orange)">Injects 15 fake SSIDs (FBI Van, SkyNet, etc.)</span>
  </div>

  <div class="panel" id="p-evil">
    <button class="btn b" onclick="runScan()">&#x1F501; Scan</button>
    <select class="inp" id="apE" style="width:200px"><option value="">-- select target --</option></select>
    <span class="lbl">or SSID:</span>
    <input class="inp" id="eSsid" placeholder="Target SSID" style="width:140px">
    <div class="sep"></div>
    <button class="btn o" onclick="startEvil()">&#x1F608; Launch Evil Twin</button>
    <button class="btn r" onclick="send('eviltwin stop')">&#x25A0; Stop</button>
  </div>

  <div class="panel" id="p-hs">
    <button class="btn b" onclick="runScan()">&#x1F501; Scan</button>
    <select class="inp" id="apH" style="width:220px"><option value="">-- select AP --</option></select>
    <div class="sep"></div>
    <button class="btn g" onclick="startHs()">&#x25B6; Capture Handshake</button>
    <button class="btn r" onclick="send('handshake stop')">&#x25A0; Stop</button>
    <button class="btn y" id="dlBtn" onclick="send('handshake get')" disabled>&#x2B07; Download PCAP</button>
    <span class="lbl" id="hsStatus" style="color:var(--green)">EAPOL: 0/4</span>
  </div>

  <div class="panel" id="p-ps">
    <span class="lbl">Target IP:</span>
    <input class="inp" id="psIp" placeholder="192.168.4.2" style="width:130px">
    <span class="lbl">Ports:</span>
    <input class="inp" id="psS" value="1" style="width:52px">
    <span class="lbl">-</span>
    <input class="inp" id="psE" value="1024" style="width:52px">
    <button class="btn g" onclick="startPS()">&#x1F50D; Scan Ports</button>
  </div>

  <div class="panel" id="p-wd">
    <button class="btn g" onclick="send('wardrive start')">&#x1F5FA; Start Wardriving</button>
    <button class="btn r" onclick="send('wardrive stop')">&#x25A0; Stop</button>
    <div class="sep"></div>
    <span class="lbl">Cycles ch1-13 every 3s — logs all APs found</span>
  </div>

  <div class="panel" id="p-crack">
    <span class="lbl">PCAP File:</span>
    <input type="file" id="pcapFile" class="inp" style="width:180px">
    <span class="lbl">Wordlist:</span>
    <input type="file" id="dictFile" class="inp" style="width:180px">
    <button class="btn o" onclick="startJsCrack()">&#x1F513; Start JS Crack</button>
    <div class="sep"></div>
    <span class="lbl" id="crackStatus" style="color:var(--orange)">Offline PBKDF2 brute-force</span>
  </div>
</div>


<div id="terminal"></div>

<script>
var ws, pcapChunks=[], pcapTotal=0, history=[], histIdx=-1, apList=[];
function v(id){return document.getElementById(id).value;}
function el(id){return document.getElementById(id);}

function tab(id,btn){
  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('act');});
  document.querySelectorAll('.tb').forEach(function(b){b.classList.remove('act');});
  el('p-'+id).classList.add('act'); btn.classList.add('act');
}

function init(){
  log('sys','╔═══════════════════════════════════════════╗');
  log('sys','║    ESP32 Dual-Node Pen-Tool  v3.0         ║');
  log('sys','╚═══════════════════════════════════════════╝');
  log('info','Use the tabs and buttons above to run attacks.');
  log('info','Click  Scan APs  first to populate the AP dropdowns.');
  log('info','Connecting to WebSocket...');
  connect();
}

function connect(){
  ws=new WebSocket('ws://'+location.hostname+':81/');
  ws.onopen=function(){setDot(true);log('sys','✔ WebSocket connected.');};
  ws.onclose=function(){setDot(false);setNode2(false);log('err','✖ Disconnected — reconnecting in 3s...');setTimeout(connect,3000);};
  ws.onerror=function(){log('err','⚠ WebSocket error.');};
  ws.onmessage=function(e){handleMsg(e.data);};
}

function handleMsg(raw){
  // PCAP streaming
  if(raw.startsWith('[PCAP:START:')){
    var m=raw.match(/\[PCAP:START:(\d+):(\d+)\]/);
    if(m){pcapTotal=parseInt(m[1]);pcapChunks=[];log('hs','[PCAP] Receiving '+pcapTotal+' chunks...');}
    return;
  }
  if(raw.startsWith('[PCAP:')&&raw!=='[PCAP:END]'){
    var m=raw.match(/\[PCAP:(\d+)\/\d+:(.+)\]/);
    if(m)pcapChunks[parseInt(m[1])]=m[2];
    return;
  }
  if(raw==='[PCAP:END]'){buildPcap();return;}

  // Node2 heartbeat reply
  if(raw==='[Node2] PONG'){setNode2(true);return;}

  // Badge updates
  if(raw.indexOf('Monitor Mode Started')>=0)  setBadge('monBadge','MON:ON',true);
  if(raw.indexOf('Monitor Mode Stopped')>=0)  setBadge('monBadge','MON:OFF',false);
  if(raw.indexOf('Deauth flood')>=0)           setBadge('deauthBadge','DEAUTH:ON',true);
  if(raw.indexOf('Deauth stopped')>=0)         setBadge('deauthBadge','DEAUTH:OFF',false);
  if(raw.indexOf('EvilTwin')>=0&&raw.indexOf('active')>=0) setBadge('evilBadge','EVIL:ON',true);
  if(raw.indexOf('Evil Twin stopped')>=0)      setBadge('evilBadge','EVIL:OFF',false);

  // Node2 online on ANY reply
  if(raw.startsWith('[Node2]')||raw.startsWith('[Monitor]')||raw.startsWith('[Scan]')||
     raw.startsWith('[WD]')||raw.startsWith('[Handshake]')||raw.startsWith('[EvilTwin]')||
     raw.startsWith('[PortScan]')||raw.startsWith('[Wardrive]')){
    setNode2(true);
  }

  // EAPOL / handshake tracking
  var hm=raw.match(/EAPOL frame #(\d+)/);
  if(hm){el('hsStatus').textContent='EAPOL: '+hm[1]+'/4';}
  if(raw.indexOf('4-way handshake complete')>=0){el('dlBtn').disabled=false;}

  // AP scan results → dropdown populate
  if(raw.startsWith('[Scan]')||raw.startsWith('[WD]')) populateAp(raw);

  // Classify line colour
  var cls='out';
  if(raw.startsWith('[Scan]')||raw.startsWith('[WD]')||raw.startsWith('[Wardrive]'))cls='scan';
  if(raw.startsWith('[Handshake]')||raw.startsWith('[PCAP]'))cls='hs';
  if(raw.startsWith('[EvilTwin]')||raw.indexOf('CAPTURED')>=0)cls='evil';
  if(raw.startsWith('[PortScan]'))cls='info';
  if(raw.indexOf('ERROR')>=0||raw.startsWith('[Node2] FATAL'))cls='err';
  if(raw.startsWith('[ESP1]'))cls='sys';
  if(raw.startsWith('[Monitor]'))cls='info';
  if(raw.startsWith('[Node2] Unknown'))cls='err';
  log(cls,raw);
}

function populateAp(raw){
  var m=raw.match(/([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*\|\s*ch(\d+)\s*\|\s*(-?\d+)dBm\s*\|\s*(.*)/);
  if(!m)return;
  var bssid=m[1].toUpperCase(), ch=m[2], rssi=m[3], ssid=(m[4]||'').trim();
  // Avoid duplicate BSSIDs
  if(apList.find(function(x){return x.bssid===bssid;})) return;
  apList.push({bssid:bssid,ssid:ssid,ch:ch});
  var lbl='ch'+ch+' '+rssi+'dBm | '+bssid+' | '+ssid.substring(0,18);
  ['apD','apE','apH','apS'].forEach(function(id){
    var s=el(id);if(!s)return;
    var o=document.createElement('option');o.value=bssid;o.textContent=lbl;s.appendChild(o);
  });
}

function send(cmd){
  if(!cmd||!cmd.trim())return;
  log('inp-ln','> '+cmd);
  if(ws&&ws.readyState===WebSocket.OPEN){
    ws.send(cmd);
  } else {
    log('err','✖ Not connected to ESP32! Reconnecting...');
    connect();
  }
}
function runScan(){
  apList=[];
  ['apD','apE','apH','apS'].forEach(function(id){
    var s=el(id);if(!s)return;while(s.options.length>1)s.remove(1);
  });
  send('scan');
}
function startDeauth(){
  var bssid=v('apD').trim();
  if(!bssid){log('err','Select an AP first.');return;}
  var ap=apList.find(function(x){return x.bssid===bssid;});
  var ch=ap?ap.ch:'1';
  var cli=v('dCli').trim()||'FF:FF:FF:FF:FF:FF';
  send('deauth '+bssid+' '+ch+' '+cli);
}
function startEvil(){
  var bssid=v('apE'),ssid=v('eSsid').trim();
  if(!ssid&&bssid){var a=apList.find(function(x){return x.bssid===bssid;});if(a)ssid=a.ssid;}
  if(!ssid){log('err','Enter or select an SSID.');return;}
  send('eviltwin '+ssid);
}
function startHs(){
  var bssid=v('apH').trim();
  if(!bssid){log('err','Select an AP first.');return;}
  var ap=apList.find(function(x){return x.bssid===bssid;});
  var ch=ap?ap.ch:'1';
  el('dlBtn').disabled=true; el('hsStatus').textContent='EAPOL: 0/4';
  send('handshake '+bssid+' '+ch);
}
function startPS(){
  var ip=v('psIp').trim();if(!ip){log('err','Enter target IP.');return;}
  send('portscan '+ip+' '+v('psS')+' '+v('psE'));
}
function buildPcap(){
  try{
    var b64='';for(var i=0;i<pcapTotal;i++)b64+=(pcapChunks[i]||'');
    var bin=atob(b64),buf=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
    var a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([buf],{type:'application/octet-stream'}));
    a.download='handshake.cap';a.click();
    log('hs','[PCAP] handshake.cap saved ('+bin.length+' bytes). Use: hashcat -m 22000 or aircrack-ng');
  }catch(ex){log('err','PCAP error: '+ex);}
}
function log(cls,txt){
  var t=el('terminal'),s=document.createElement('span');
  s.className='ln '+cls; s.textContent=txt; t.appendChild(s); t.scrollTop=t.scrollHeight;
  // keep terminal manageable
  while(t.children.length>500) t.removeChild(t.firstChild);
}
function setDot(on){
  el('wsDot').className='wsd'+(on?' on':'');
  el('wsLbl').textContent=on?'Connected':'Disconnected';
}
function setNode2(on){
  el('n2Dot').className='node2-dot'+(on?' on':'');
  el('n2Lbl').textContent=on?'Node2:ON':'Node2:OFF';
}
function setBadge(id,txt,on){var b=el(id);b.textContent=txt;b.className='badge'+(on?' on':'');}
function clearTerm(){el('terminal').innerHTML='';}

// --- WPA2 JS Cracker Logic ---
async function pbkdf2(pwd, salt, iters, len) {
  const enc = new TextEncoder();
  const keyObj = await crypto.subtle.importKey('raw', enc.encode(pwd), {name:'PBKDF2'}, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt:enc.encode(salt), iterations:iters, hash:'SHA-1'}, keyObj, len*8);
  return new Uint8Array(bits);
}

function startJsCrack() {
  const pFile = el('pcapFile').files[0];
  const dFile = el('dictFile').files[0];
  if(!pFile || !dFile) { log('err', 'Select both PCAP and Wordlist files.'); return; }
  
  el('crackStatus').textContent = 'Parsing...';
  log('info', '[Cracker] To keep this dashboard fast, only basic string matching on SSID hash is simulated here. Full PCAP parsing in JS requires a heavyweight library. Please use Hashcat natively on your PC with the downloaded PCAP for real attacks. (Browser PBKDF2 demonstration is active).');
  
  const reader = new FileReader();
  reader.onload = async function(e) {
    const text = e.target.result;
    const words = text.split(/\\r?\\n/).filter(w => w.length >= 8);
    log('info', '[Cracker] Loaded ' + words.length + ' passphrases. Simulating PBKDF2 hash generation...');
    
    el('crackStatus').textContent = 'Cracking...';
    let count = 0;
    const t0 = performance.now();
    
    // Simulate hashing the first 100 words (browsers will freeze if we sync-loop too many)
    const limit = Math.min(100, words.length);
    for(let i=0; i<limit; i++) {
      // WPA2 uses 4096 iterations of SHA-1
      await pbkdf2(words[i], 'DummySSID', 4096, 32); 
      count++;
    }
    const t1 = performance.now();
    const speed = Math.round((limit / (t1-t0)) * 1000);
    
    log('info', '[Cracker] Computed ' + limit + ' PMKs at ' + speed + ' hashes/sec.');
    log('hs', '[Cracker] Real cracking requires a dedicated GPU. JS Browser cracking is 10,000x slower than Hashcat.');
    el('crackStatus').textContent = 'Done. Speed: ' + speed + ' h/s';
  };
  reader.readAsText(dFile);
}


const wolfM = [
"                                              ",
"         ::                                   ",
"        :::                                   ",
"       :::                                    ",
"       :::                                    ",
"       ::::                                   ",
"       ::::                                   ",
"       :::::                                  ",
"        :::::                                 ",
"         :::::  ::                            ",
"          ::::::::                            ",
"           ::::::                             ",
"            ::::::                            ",
"            :::::::                           ",
"             :::::::                          ",
"              ::::::::::::::::::::::::::::    ",
"              ::::::::::::::::::::::::::::::  ",
"              ::::::::::::::::::::::::::::::  ",
"               :::::::::::::::::::::::::::::  ",
"                ::::::::::::::::::::::::::::  ",
"                 :::::::::::::::::::::::::::  ",
"                  ::::::::::::::::::::::::::::",
"                  ::::::::::::::::::::::::::::",
"                   :::::::::::::::::::::::::::",
"           :::      ::::::::::::::::::::::::::",
"          ::::::    ::::::::::::::::::::::::::",
"         ::::::::    :::::::::::::::::::::::::",
"         :::::::::   :::::::::::::::::::::::::",
"          :::::::::  :::::::::::::::::::::::::",
"           ::::::::: :::::::::::::::::::::    ",
"            :::::::::::::::::::::::::::       ",
"              :::::::::::::::::::::::  :::    ",
"               ::::::::::::::::::::  ::::::   ",
"               ::::::::::::::::::: ::::::     ",
"               ::::::::::::::::::::::::::     ",
"               ::::::::::::::::::::::::::     ",
"               ::::::::::::::::::::::::::     ",
"              :::::::::::::::::::::::::::     ",
"             :::::: :::::::::::::  ::::::     ",
"            ::::::   ::::::::::    ::::::     ",
"           ::::::     :::::        :::::      ",
"          ::::::       :::         :::::      ",
"         ::::::                    ::::       ",
"         :::::                     ::::       ",
"         ::::                      ::::       ",
"         :::::                      :::       ",
"   :::::::::::::::::::::::::::      :::       ",
"  :::::::::::::::::::::::::::::::::::::       ",
"  :::::::::::::::::::::::::::::::::::::       ",
"   ::::::::::::::::::::::::::::::::::::       "
];

function drawW() {
  let h='';
  for(let i=0;i<wolfM.length;i++){
    let r='';
    for(let j=0;j<wolfM[i].length;j++){
      r += wolfM[i][j]===' '?' ':(Math.random()>0.5?'1':'0');
    }
    h+=r+'\n';
  }
  let w = el('wolf-sidebar');
  if(w) w.textContent = h;
}
setInterval(drawW, 120);

window.addEventListener('load',init);
</script></div></div></body></html>
)rawliteral";

// ═════════════════════════════════════════════════════════════════
//  ISR-safe enqueue (called from ESP-NOW receive ISR)
// ═════════════════════════════════════════════════════════════════
void IRAM_ATTR enqueueMsg(const char* msg) {
  int next = (qTail + 1) % QUEUE_SIZE;
  if (next == qHead) { queueOverflow = true; return; }
  strncpy(msgQueue[qTail], msg, MSG_LEN - 1);
  msgQueue[qTail][MSG_LEN - 1] = '\0';
  qTail = next;
}

// ═════════════════════════════════════════════════════════════════
//  ESP-NOW receive callback (runs in WiFi task / ISR context)
// ═════════════════════════════════════════════════════════════════
void OnDataRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if (len <= 0 || len >= MSG_LEN) return;
  char buf[MSG_LEN];
  memcpy(buf, data, len);
  buf[len] = '\0';
  enqueueMsg(buf);
}

// ═════════════════════════════════════════════════════════════════
//  Send a command to ESP2 via ESP-NOW (called from loop)
// ═════════════════════════════════════════════════════════════════
bool sendToESP2(const char* cmd) {
  size_t len = strlen(cmd);
  if (len >= MSG_LEN) len = MSG_LEN - 1;
  Serial.printf("[ESP-NOW TX] '%s' (%d bytes)\n", cmd, (int)len);
  esp_err_t r = esp_now_send(ESP2_MAC, (const uint8_t*)cmd, len);
  if (r != ESP_OK) {
    char err[120];
    snprintf(err, sizeof(err),
      "[ESP1] ERROR: ESP-NOW send failed (err=0x%X). "
      "Common causes: wrong ESP2_MAC, ESP2 not powered, channel mismatch.", r);
    wsServer.broadcastTXT(err);
    Serial.println(err);
    return false;
  }
  Serial.println("[ESP-NOW TX] queued OK");
  return true;
}

// ═════════════════════════════════════════════════════════════════
//  WebSocket event handler
// ═════════════════════════════════════════════════════════════════
void onWsEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_CONNECTED: {
      activeClient = (int8_t)num;
      Serial.printf("[WS] Client #%u connected\n", num);
      wsServer.sendTXT(num, "[ESP1] Security Suite ready. Waiting for Node2 heartbeat...");
      // Immediately probe Node2
      sendToESP2("ping");
      break;
    }
    case WStype_DISCONNECTED:
      if (activeClient == (int8_t)num) activeClient = -1;
      Serial.printf("[WS] Client #%u disconnected\n", num);
      break;

    case WStype_TEXT: {
      if (length == 0) return;
      char cmd[MSG_LEN];
      size_t l = (length >= MSG_LEN) ? MSG_LEN - 1 : length;
      memcpy(cmd, payload, l);
      cmd[l] = '\0';
      Serial.printf("[WS→] %s\n", cmd);

      // Forward to ESP2
      sendToESP2(cmd);
      break;
    }
    default: break;
  }
}

// ═════════════════════════════════════════════════════════════════
//  Setup
// ═════════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\n==== ESP32 Node 1 — Pen-Tool Gateway ====");

  // Start as AP+STA so ESP-NOW works alongside the AP
  WiFi.mode(WIFI_AP_STA);
  // Force AP to channel 1 — ESP2 must initialise on channel 1 as well
  WiFi.softAP(AP_SSID, AP_PASS, 1, 0, 4);
  delay(100);
  Serial.printf("AP: %s  |  IP: %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());
  Serial.printf("AP  MAC: %s\n", WiFi.softAPmacAddress().c_str());
  Serial.printf("STA MAC: %s\n", WiFi.macAddress().c_str());

  // ── ESP-NOW ──────────────────────────────────────
  if (esp_now_init() != ESP_OK) {
    Serial.println("FATAL: ESP-NOW init failed!");
    while (true) delay(1000);
  }
  esp_now_register_recv_cb(OnDataRecv);

  // Register ESP2 peer
  // IMPORTANT: channel MUST match the channel ESP2 is sitting on.
  // ESP2 stays on channel 1 at boot (and returns to it after scans).
  // ESP1's AP is also on channel 1. So we hard-code 1 here.
  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, ESP2_MAC, 6);
  peerInfo.channel  = 1;          // AP is always on channel 1
  peerInfo.encrypt  = false;
  peerInfo.ifidx    = WIFI_IF_AP; // send via AP interface

  Serial.printf("Targeting ESP2 MAC: %02X:%02X:%02X:%02X:%02X:%02X on ch1\n",
    ESP2_MAC[0],ESP2_MAC[1],ESP2_MAC[2],ESP2_MAC[3],ESP2_MAC[4],ESP2_MAC[5]);

  if (esp_now_add_peer(&peerInfo) != ESP_OK)
    Serial.println("ERROR: Failed to add ESP2 peer — double-check ESP2_MAC[]");
  else
    Serial.println("ESP-NOW peer (Node 2) registered OK.");

  // ── HTTP ──────────────────────────────────────────
  httpServer.on("/", HTTP_GET, []() {
    httpServer.send_P(200, "text/html", HTML_PAGE);
  });
  httpServer.onNotFound([]() {
    httpServer.sendHeader("Location", "/");
    httpServer.send(302);
  });
  httpServer.begin();
  Serial.println("HTTP server started (port 80).");

  // ── WebSocket ─────────────────────────────────────
  wsServer.begin();
  wsServer.onEvent(onWsEvent);
  Serial.println("WebSocket server started (port 81).");

  Serial.printf("\nConnect to Wi-Fi '%s' (pass: %s)\n", AP_SSID, AP_PASS);
  Serial.println("Then open  http://192.168.4.1  in your browser.");
  Serial.println("=========================================\n");

  lastHeartbeat = millis();
}

// ═════════════════════════════════════════════════════════════════
//  Loop
// ═════════════════════════════════════════════════════════════════
void loop() {
  wsServer.loop();
  httpServer.handleClient();

  // ── Drain message queue → broadcast to WebSocket ──
  while (qHead != qTail) {
    wsServer.broadcastTXT(msgQueue[qHead]);
    qHead = (qHead + 1) % QUEUE_SIZE;
  }

  if (queueOverflow) {
    wsServer.broadcastTXT("[ESP1] ⚠ Queue overflow — some messages were dropped");
    queueOverflow = false;
  }

  // ── Heartbeat ping to Node 2 ──────────────────────
  unsigned long now = millis();
  if (now - lastHeartbeat >= HEARTBEAT_MS) {
    lastHeartbeat = now;
    sendToESP2("ping");
  }
}
