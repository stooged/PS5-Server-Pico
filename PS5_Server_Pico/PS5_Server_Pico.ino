#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <WebServerSecure.h>
#include <LittleFS.h>
#include <LEAmDNS.h>
#include "etahen.h"
#include "offsets.h"
#include "exploit.h"



static const char serverCert[] = "-----BEGIN CERTIFICATE-----\r\nMIIC1DCCAj2gAwIBAgIUFQgjEtkNYfmrrpNQKHVNl3+dl08wDQYJKoZIhvcNAQEL\r\nBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAcM\r\nB0ZyZW1vbnQxDDAKBgNVBAoMA2VzcDEMMAoGA1UECwwDZXNwMQwwCgYDVQQDDANl\r\nc3AxHDAaBgkqhkiG9w0BCQEWDWVzcEBlc3AubG9jYWwwHhcNMjEwMjIxMDAwMDQ4\r\nWhcNNDMwNzI4MDAwMDQ4WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv\r\ncm5pYTEQMA4GA1UEBwwHRnJlbW9udDEMMAoGA1UECgwDZXNwMQwwCgYDVQQLDANl\r\nc3AxDDAKBgNVBAMMA2VzcDEcMBoGCSqGSIb3DQEJARYNZXNwQGVzcC5sb2NhbDCB\r\nnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsrfFqlV5H0ajdAkkZ51HTOseOjYj\r\nNiaUD4MA5mIRonnph6EKIWb9Yl85vVa6yfVkGn3TFebQ96MMdTfZgLuP4ryCwe6Y\r\n+tZs2g6TjGbR0O6yuA8wQ2Ln7E0T05C8oOl88SGNV4tVL6hz64oMzuVebVDo0J9I\r\nybvL0O/LhMvC4x8CAwEAAaNTMFEwHQYDVR0OBBYEFCMQIU+pZQDVySXejfbIYbLQ\r\ncLXiMB8GA1UdIwQYMBaAFCMQIU+pZQDVySXejfbIYbLQcLXiMA8GA1UdEwEB/wQF\r\nMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAFHPz3YhhXQYiERTGzt8r0LhNWdggr7t0\r\nWEVuAoEukjzv+3DVB2O+56NtDa++566gTXBGGar0pWfCwfWCEu5K6MBkBdm6Ub/A\r\nXDy+sRQTqH/jTFFh5lgxeq246kHWHGRad8664V5PoIh+OSa0G3CEB+BXy7WF82Qq\r\nqx0X6E/mDUU=\r\n-----END CERTIFICATE-----";
static const char serverKey[] = "-----BEGIN PRIVATE KEY-----\r\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALK3xapVeR9Go3QJ\r\nJGedR0zrHjo2IzYmlA+DAOZiEaJ56YehCiFm/WJfOb1Wusn1ZBp90xXm0PejDHU3\r\n2YC7j+K8gsHumPrWbNoOk4xm0dDusrgPMENi5+xNE9OQvKDpfPEhjVeLVS+oc+uK\r\nDM7lXm1Q6NCfSMm7y9Dvy4TLwuMfAgMBAAECgYEApKFbSeyQtfnpSlO9oGEmtDmG\r\nT9NdHl3tWFiydId0fTpWoKT9YwWvdnYIB12klbQicbDkyTEl4Gjnafd3ufmNsaH8\r\nZ9twopIdvvWDvGPIqGNjvTYcuczpXmQWiUnG5OTiVWI1XuZa3uZEGSFK9Ra6bE4g\r\nG2xklGZGdaqqcd6AVhECQQDnBXVXwBxExxSFppL8KUtWgyXAvJAEvkzvTOQfcCel\r\naIM5EEUofB7WZeMtDEKgBtoBl+i5PP+GnDF0zsjDFx2nAkEAxgqVQii6zURSVE2T\r\niJDihySXJ2bmLJUjRIi1nCs64I9Oz4fECVvGwZ1XU8Uzhh3ylyBSG2HjhzA5sTSC\r\n1a/tyQJAOgE12EWFE4PE1FXhm+ymXN9q8DyoEHjTilYNBRO88JwQLpi2NJcNixlj\r\n8+CbLeDqhfHlXfVB10OKa2CsKce5CwJAbhaN+DQJ+3dCSOjC3YSk2Dkn6VhTFW9m\r\nJn/UbNa/KPug9M5k1Er3RsO/OqsBxEk7hHUMD3qv74OIXpBxNnZQuQJASlwk5HZT\r\n7rULkr72fK/YYxkS0czBDIpTKqwklxU+xLSGWkSHvSvl7sK4TmQ1w8KVpjKlTCW9\r\nxKbbW0zVmGN6wQ==\r\n-----END PRIVATE KEY-----";

DNSServer dnsServer;
WebServer webServer;
WebServerSecure swebServer(443);
ServerSessions serverCache(5);
#define FILESYS LittleFS
boolean hasEnabled = false;
boolean hasStarted = false;
File upFile;
String firmwareVer = "1.00";


//-------------------DEFAULT SETTINGS------------------//

// use config.ini [ true / false ]
#define USECONFIG true  // this will allow you to change these settings below via the admin webpage. \
                        // if you want to permanently use the values below then set this to false.

// access point
String AP_SSID = "PS5_WEB_AP";
String AP_PASS = "password";
IPAddress Server_IP(10, 1, 1, 1);
IPAddress Subnet_Mask(255, 255, 255, 0);

// wifi
boolean connectWifi = false;  // enabling this option will disable the access point
String WIFI_SSID = "Home_WIFI";
String WIFI_PASS = "password";
String WIFI_HOSTNAME = "ps5.local";

//server port
int WEB_PORT = 80;

//exfathax Wait(milliseconds)
int USB_WAIT = 10000;

//-----------------------------------------------------//
#include "pages.h"


String split(String str, String from, String to) {
  String tmpstr = str;
  tmpstr.toLowerCase();
  from.toLowerCase();
  to.toLowerCase();
  int pos1 = tmpstr.indexOf(from);
  int pos2 = tmpstr.indexOf(to, pos1 + from.length());
  String retval = str.substring(pos1 + from.length(), pos2);
  return retval;
}


bool instr(String str, String search) {
  int result = str.indexOf(search);
  if (result == -1) {
    return false;
  }
  return true;
}


String formatBytes(size_t bytes) {
  if (bytes < 1024) {
    return String(bytes) + " B";
  } else if (bytes < (1024 * 1024)) {
    return String(bytes / 1024.0) + " KB";
  } else if (bytes < (1024 * 1024 * 1024)) {
    return String(bytes / 1024.0 / 1024.0) + " MB";
  } else {
    return String(bytes / 1024.0 / 1024.0 / 1024.0) + " GB";
  }
}



String urlencode(String str) {
  String encodedString = "";
  char c;
  char code0;
  char code1;
  char code2;
  for (int i = 0; i < str.length(); i++) {
    c = str.charAt(i);
    if (c == ' ') {
      encodedString += '+';
    } else if (isalnum(c)) {
      encodedString += c;
    } else {
      code1 = (c & 0xf) + '0';
      if ((c & 0xf) > 9) {
        code1 = (c & 0xf) - 10 + 'A';
      }
      c = (c >> 4) & 0xf;
      code0 = c + '0';
      if (c > 9) {
        code0 = c - 10 + 'A';
      }
      code2 = '\0';
      encodedString += '%';
      encodedString += code0;
      encodedString += code1;
    }
    yield();
  }
  encodedString.replace("%2E", ".");
  return encodedString;
}


bool loadFromFileSys(String path) {
  path = webServer.urlDecode(path);
  String dataType = mime::getContentType(path);
  
  if (path.equals("/connecttest.txt")) {
    webServer.setContentLength(22);
    webServer.send(200, "text/plain", "Microsoft Connect Test");
    return true;
  }
  if (path.equals("/config.ini")) {
    return false;
  }
  if (path.endsWith("/")) {
    path += "index.html";
  }

  if (path.endsWith("updatelist.xml")) {
    webServer.send(200, "application/xml", updatelistData);
    return true;
  }
  
  if (instr(path, "/document/") && instr(path, "/ps5/")) {
    webServer.sendHeader("Location", "http://" + WIFI_HOSTNAME + "/index.html");
    webServer.send(302, "text/html", "");
    return true;
  }


  if (path.endsWith("index.html"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), index_gz, sizeof(index_gz));
    return true;
  }


  if (path.endsWith("3.00.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o3_00_gz, sizeof(o3_00_gz));
    return true;
  }

  if (path.endsWith("3.10.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o3_10_gz, sizeof(o3_10_gz));
    return true;
  }

  if (path.endsWith("3.20.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o3_20_gz, sizeof(o3_20_gz));
    return true;
  }

  if (path.endsWith("3.21.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o3_21_gz, sizeof(o3_21_gz));
    return true;
  }

  if (path.endsWith("4.00.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o4_00_gz, sizeof(o4_00_gz));
    return true;
  }

  if (path.endsWith("4.02.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o4_02_gz, sizeof(o4_02_gz));
    return true;
  }

  if (path.endsWith("4.03.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o4_03_gz, sizeof(o4_03_gz));
    return true;
  }

  if (path.endsWith("4.50.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o4_50_gz, sizeof(o4_50_gz));
    return true;
  }

  if (path.endsWith("4.51.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), o4_51_gz, sizeof(o4_51_gz));
    return true;
  }


  if (path.endsWith("custom_host_stuff.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), custom_host_stuff_gz, sizeof(custom_host_stuff_gz));
    return true;
  }

  if (path.endsWith("exploit.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), exploit_gz, sizeof(exploit_gz));
    return true;
  }

  if (path.endsWith("int64.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), int64_gz, sizeof(int64_gz));
    return true;
  }

  if (path.endsWith("main.css"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, "text/css", main_gz, sizeof(main_gz));
    return true;
  }

  if (path.endsWith("rop.js"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), rop_gz, sizeof(rop_gz));
    return true;
  }

  if (path.endsWith("rop_slave.js"))
  {    
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), rop_slave_gz, sizeof(rop_slave_gz));
    return true;
  }

  if (path.endsWith("webkit.js"))
  {   
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), webkit_gz, sizeof(webkit_gz));
    return true;
  }

  if (path.endsWith("payload_map.js"))
  {
    handlePayloads();
    return true;
  }


  if (path.endsWith("ethen.bin"))
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send(200, dataType.c_str(), etahen, sizeof(etahen));
    return true;
  }


  File dataFile;
  dataFile = FILESYS.open(path, "r");
  if (!dataFile) {
    if (path.endsWith("style.css")) {
      webServer.sendHeader("Content-Encoding", "gzip");
      webServer.send(200, "text/css", style_gz, sizeof(style_gz));
      return true;
    }
    return false;
  }
  if (webServer.hasArg("download")) {
    dataType = "application/octet-stream";
    String dlFile = path;
    if (dlFile.startsWith("/")) {
      dlFile = dlFile.substring(1);
    }
    webServer.sendHeader("Content-Disposition", "attachment; filename=\"" + dlFile + "\"");
    webServer.sendHeader("Content-Transfer-Encoding", "binary");
  } 

  if (webServer.streamFile(dataFile, dataType) != dataFile.size()) {
    //Sent less data than expected!;
  }
  dataFile.close();
  return true;
}


void handleNotFound() {
  if (loadFromFileSys(webServer.uri())) {
    return;
  }
  String message = "\n\n";
  message += "URI: ";
  message += webServer.uri();
  message += "\nMethod: ";
  message += (webServer.method() == HTTP_GET) ? "GET" : "POST";
  message += "\nArguments: ";
  message += webServer.args();
  message += "\n";
  for (uint8_t i = 0; i < webServer.args(); i++) {
    message += " NAME:" + webServer.argName(i) + "\n VALUE:" + webServer.arg(i) + "\n";
  }
  webServer.send(404, "text/plain", "Not Found");
}

void handleFileUpload() {
  if (webServer.uri() != "/upload.html") {
    webServer.send(500, "text/plain", "Internal Server Error");
    return;
  }
  HTTPUpload& upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    if (!filename.startsWith("/")) {
      filename = "/" + filename;
    }
    if (filename.equals("/config.ini")) { return; }
    upFile = FILESYS.open(filename, "w");
    filename = String();
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) {
      upFile.write(upload.buf, upload.currentSize);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) {
      upFile.close();
    }
  }
}



void handleFormat() {
  FILESYS.end();
  FILESYS.format();
  FILESYS.begin();
#if USECONFIG
  writeConfig();
#endif
  webServer.sendHeader("Location", "/fileman.html");
  webServer.send(302, "text/html", "");
}


void handleDelete() {
  if (!webServer.hasArg("file")) {
    webServer.sendHeader("Location", "/fileman.html");
    webServer.send(302, "text/html", "");
    return;
  }
  String path = webServer.arg("file");
  if (FILESYS.exists("/" + path) && path != "/" && !path.equals("config.ini")) {
    FILESYS.remove("/" + path);
  }
  webServer.sendHeader("Location", "/fileman.html");
  webServer.send(302, "text/html", "");
}


void handleFileMan() {
  Dir dir = FILESYS.openDir("/");
  String output = "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>File Manager</title><link rel=\"stylesheet\" href=\"style.css\"><style>body{overflow-y:auto;} th{border: 1px solid #dddddd; background-color:gray;padding: 8px;}</style><script>function statusDel(fname) {var answer = confirm(\"Are you sure you want to delete \" + fname + \" ?\");if (answer) {return true;} else { return false; }}</script></head><body><br><table id=filetable></table><script>var filelist = [";
  int fileCount = 0;
  while (dir.next()) {
    File entry = dir.openFile("r");
    String fname = String(entry.name());
    if (fname.startsWith("/")) { fname = fname.substring(1); }
    if (fname.length() > 0 && !fname.equals("config.ini")) {
      fileCount++;
      fname.replace("|", "%7C");
      fname.replace("\"", "%22");
      output += "\"" + fname + "|" + formatBytes(entry.size()) + "\",";
    }
    entry.close();
  }
  if (fileCount == 0) {
    output += "];</script><center>No files found<br>You can upload files using the <a href=\"/upload.html\" target=\"mframe\"><u>File Uploader</u></a> page.</center></p></body></html>";
  } else {
    output += "];var output = \"\";filelist.forEach(function(entry) {var splF = entry.split(\"|\"); output += \"<tr>\";output += \"<td><a href=\\\"\" +  splF[0] + \"\\\">\" + splF[0] + \"</a></td>\"; output += \"<td>\" + splF[1] + \"</td>\";output += \"<td><a href=\\\"/\" + splF[0] + \"\\\" download><button type=\\\"submit\\\">Download</button></a></td>\";output += \"<td><form action=\\\"/delete\\\" method=\\\"post\\\"><button type=\\\"submit\\\" name=\\\"file\\\" value=\\\"\" + splF[0] + \"\\\" onClick=\\\"return statusDel('\" + splF[0] + \"');\\\">Delete</button></form></td>\";output += \"</tr>\";}); document.getElementById(\"filetable\").innerHTML = output;</script></body></html>";
  }
  webServer.setContentLength(output.length());
  webServer.send(200, "text/html", output);
}


#if USECONFIG
void handleConfig() {
  if (webServer.hasArg("ap_ssid") && webServer.hasArg("ap_pass") && webServer.hasArg("web_ip") && webServer.hasArg("web_port") && webServer.hasArg("subnet") && webServer.hasArg("wifi_ssid") && webServer.hasArg("wifi_pass") && webServer.hasArg("wifi_host") && webServer.hasArg("usbwait")) {
    AP_SSID = webServer.arg("ap_ssid");
    if (!webServer.arg("ap_pass").equals("********")) {
      AP_PASS = webServer.arg("ap_pass");
    }
    WIFI_SSID = webServer.arg("wifi_ssid");
    if (!webServer.arg("wifi_pass").equals("********")) {
      WIFI_PASS = webServer.arg("wifi_pass");
    }
    String tmpip = webServer.arg("web_ip");
    String tmpwport = webServer.arg("web_port");
    String tmpsubn = webServer.arg("subnet");
    String WIFI_HOSTNAME = webServer.arg("wifi_host");

    String tmpcw = "false";

    if (webServer.hasArg("usewifi")) {
      String tmpcval = webServer.arg("usewifi");
      if (tmpcval.equals("true")) {
        tmpcw = "true";
      }
    }

    int USB_WAIT = webServer.arg("usbwait").toInt();
    File iniFile = FILESYS.open("/config.ini", "w");
    if (iniFile) {
      iniFile.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWEBSERVER_IP=" + tmpip + "\r\nWEBSERVER_PORT=" + tmpwport + "\r\nSUBNET_MASK=" + tmpsubn + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nCONWIFI=" + tmpcw + "\r\nUSBWAIT=" + String(USB_WAIT) + "\r\n");
      iniFile.close();
    }
    String htmStr = "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"8; url=/info.html\"><style type=\"text/css\">#loader {  z-index: 1;   width: 50px;   height: 50px;   margin: 0 0 0 0;   border: 6px solid #f3f3f3;   border-radius: 50%;   border-top: 6px solid #3498db;   width: 50px;   height: 50px;   -webkit-animation: spin 2s linear infinite;   animation: spin 2s linear infinite; } @-webkit-keyframes spin {  0%  {  -webkit-transform: rotate(0deg);  }  100% {  -webkit-transform: rotate(360deg); }}@keyframes spin {  0% { transform: rotate(0deg); }  100% { transform: rotate(360deg); }} body { background-color: #1451AE; color: #ffffff; font-size: 20px; font-weight: bold; margin: 0 0 0 0.0; padding: 0.4em 0.4em 0.4em 0.6em;}   #msgfmt { font-size: 16px; font-weight: normal;}#status { font-size: 16px;  font-weight: normal;}</style></head><center><br><br><br><br><br><p id=\"status\"><div id='loader'></div><br>Config saved<br>Rebooting</p></center></html>";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/html", htmStr);
    delay(1000);
    rp2040.reboot();
  } else {
    webServer.sendHeader("Location", "/config.html");
    webServer.send(302, "text/html", "");
  }
}

void handleConfigHtml() {
  String tmpCw = "";
  String tmpAp = "";
  if (connectWifi) {
    tmpCw = "checked";
  } else {
    tmpAp = "checked";
  }
  String htmStr = "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Config Editor</title><style type=\"text/css\">body {background-color: #1451AE; color: #ffffff; font-size: 14px;font-weight: bold; margin: 0 0 0 0.0; padding: 0.4em 0.4em 0.4em 0.6em;} input[type=\"submit\"]:hover {background: #ffffff;color: green;}input[type=\"submit\"]:active { outline-color: green; color: green; background: #ffffff; }table {font-family: arial, sans-serif;border-collapse: collapse;}td {border: 1px solid #dddddd;text-align: left;padding: 8px;}th {border: 1px solid #dddddd; background-color:gray;text-align: center;padding: 8px;} input[type=radio] {appearance: none;background-color: #fff;width: 15px;height: 15px;border: 2px solid #ccc;border-radius: 2px;display: inline-grid;place-content: center;}input[type=radio]::before {content: \"\";width: 10px;height: 10px;transform: scale(0);transform-origin: bottom left;background-color: #fff;clip-path: polygon(13% 50%, 34% 66%, 81% 2%, 100% 18%, 39% 100%, 0 71%);}input[type=radio]:checked::before {transform: scale(1);}input[type=radio]:checked{background-color:#00D651;border:2px solid #00D651;} </style></head><body><form action=\"/config.html\" method=\"post\"><center><table><tr><th colspan=\"2\"><center>Access Point</center></th></tr><tr><td>AP SSID:</td><td><input name=\"ap_ssid\" value=\"" + AP_SSID + "\"></td></tr><tr><td>AP PASSWORD:</td><td><input name=\"ap_pass\" value=\"********\"></td></tr><tr><td>AP IP:</td><td><input name=\"web_ip\" value=\"" + Server_IP.toString() + "\"></td></tr><tr><td>SUBNET MASK:</td><td><input name=\"subnet\" value=\"" + Subnet_Mask.toString() + "\"></td></tr><tr><td>USE AP:</td><td><input type=\"radio\" name=\"usewifi\" value=\"false\" " + tmpAp + "></td></tr><tr><th colspan=\"2\"><center>Web Server</center></th></tr><tr><td>WEBSERVER PORT:</td><td><input name=\"web_port\" value=\"" + String(WEB_PORT) + "\"></td></tr><tr><th colspan=\"2\"><center>Wifi Connection</center></th></tr><tr><td>WIFI SSID:</td><td><input name=\"wifi_ssid\" value=\"" + WIFI_SSID + "\"></td></tr><tr><td>WIFI PASSWORD:</td><td><input name=\"wifi_pass\" value=\"********\"></td></tr><tr><td>WIFI HOSTNAME:</td><td><input name=\"wifi_host\" value=\"" + WIFI_HOSTNAME + "\"></td></tr><tr><td>USE WIFI:</td><td><input type=\"radio\" name=\"usewifi\" value=\"true\" " + tmpCw + "></tr><tr><th colspan=\"2\"><center>Auto USB Wait</center></th></tr><tr><td>WAIT TIME(ms):</td><td><input name=\"usbwait\" value=\"" + String(USB_WAIT) + "\"></td></tr></table><br><input id=\"savecfg\" type=\"submit\" value=\"Save Config\"></center></form></body></html>";
  webServer.setContentLength(htmStr.length());
  webServer.send(200, "text/html", htmStr);
}
#endif



void handleReboot() {
  webServer.sendHeader("Content-Encoding", "gzip");
  webServer.send(200, "text/html", rebooting_gz, sizeof(rebooting_gz));
  delay(1000);
  rp2040.reboot();
}


void handleUploadHtml() {
  webServer.sendHeader("Content-Encoding", "gzip");
  webServer.send(200, "text/html", upload_gz, sizeof(upload_gz));
}


void handleFormatHtml() {
  webServer.sendHeader("Content-Encoding", "gzip");
  webServer.send(200, "text/html", format_gz, sizeof(format_gz));
}


void handleAdminHtml() {
  webServer.sendHeader("Content-Encoding", "gzip");
  webServer.send(200, "text/html", admin_gz, sizeof(admin_gz));
}


void handleRebootHtml() {
  webServer.sendHeader("Content-Encoding", "gzip");
  webServer.send(200, "text/html", reboot_gz, sizeof(reboot_gz));
}


void handleInfo() {
  FSInfo fs_info;
  FILESYS.info(fs_info);
  String output = "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>System Information</title><link rel=\"stylesheet\" href=\"style.css\"></head>";
  output += "<hr>###### Software ######<br><br>";
  output += "Firmware version " + firmwareVer + "<br><hr>";
  output += "###### MCU ######<br><br>";
  output += "Chip Id: " + String(rp2040.getChipID()) + "<br>";
  output += "CPU frequency: " + String(rp2040.f_cpu()) + " Hz<br>";
  output += "MCU temp: " + String(analogReadTemp()) + " &deg;C<br>";
  output += "Total Heap: " + formatBytes(rp2040.getTotalHeap()) + "<br>";
  output += "Used Heap: " + formatBytes(rp2040.getUsedHeap()) + "<br>";
  output += "Free Heap: " + formatBytes(rp2040.getFreeHeap()) + "<br><hr>";
  output += "###### File system (LittleFS) ######<br><br>";
  output += "Total space: " + formatBytes(fs_info.totalBytes) + "<br>";
  output += "Used space: " + formatBytes(fs_info.usedBytes) + "<br>";
  output += "Block size: " + String(fs_info.blockSize) + "<br>";
  output += "Page size: " + String(fs_info.pageSize) + "<br>";
  output += "Maximum open files: " + String(fs_info.maxOpenFiles) + "<br>";
  output += "Maximum path length: " + String(fs_info.maxPathLength) + "<br><hr>";
  output += "</html>";
  webServer.setContentLength(output.length());
  webServer.send(200, "text/html", output);
}



void handlePayloads()
{
  String output = "const payload_map =\r\n[";
  output += "{\r\n";
  output += "displayTitle: 'etaHEN',\r\n"; //internal etahen bin
  output += "description: 'Runs With 3.xx and 4.xx. FPKG enabler For FW 4.03-4.51 Only.',\r\n";  
  output += "fileName: 'ethen.bin',\r\n";
  output += "author: 'LightningMods_, sleirsgoevy, ChendoChap, astrelsky, illusion',\r\n";
  output += "source: 'https://github.com/LightningMods/etaHEN',\r\n";
  output += "version: '1.2 beta'\r\n}\r\n";
  
  Dir dir = FILESYS.openDir("/");
  while(dir.next())
  {
    File file = dir.openFile("r");
    String fname = String(file.name());
    fname.replace("/", "");
    if (fname.endsWith(".gz"))
    {
      fname = fname.substring(0, fname.length() - 3);
    }
    if (fname.length() > 0 && !file.isDirectory() && fname.endsWith(".bin") || fname.endsWith(".elf"))
    {
      String fnamev = fname;
      fnamev.replace(".bin", "");
      fnamev.replace(".elf", "");
      output += ",{\r\n";
      output += "displayTitle: '" + fnamev + "',\r\n";
      output += "description: '" + fname + "',\r\n";  
      output += "fileName: '" + fname + "',\r\n";
      output += "author: '',\r\n";
      output += "source: '',\r\n";
      output += "version: '1'\r\n}\r\n";
    }
    file.close();
  }
  output += "\r\n];";
  webServer.setContentLength(output.length());
  webServer.send(200, "application/javascript", output);
}



#if USECONFIG
void writeConfig() {
  File iniFile = FILESYS.open("/config.ini", "w");
  if (iniFile) {
    String tmpcw = "false";
    if (connectWifi) { tmpcw = "true"; }
    iniFile.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWEBSERVER_IP=" + Server_IP.toString() + "\r\nWEBSERVER_PORT=" + String(WEB_PORT) + "\r\nSUBNET_MASK=" + Subnet_Mask.toString() + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nCONWIFI=" + tmpcw + "\r\nUSBWAIT=" + String(USB_WAIT) + "\r\n");
    iniFile.close();
  }
}
#endif


void startFileSystem() {
  if (FILESYS.begin()) {
#if USECONFIG
    if (FILESYS.exists("/config.ini")) {
      File iniFile = FILESYS.open("/config.ini", "r");
      if (iniFile) {
        String iniData;
        while (iniFile.available()) {
          char chnk = iniFile.read();
          iniData += chnk;
        }
        iniFile.close();

        if (instr(iniData, "AP_SSID=")) {
          AP_SSID = split(iniData, "AP_SSID=", "\r\n");
          AP_SSID.trim();
        }

        if (instr(iniData, "AP_PASS=")) {
          AP_PASS = split(iniData, "AP_PASS=", "\r\n");
          AP_PASS.trim();
        }

        if (instr(iniData, "WEBSERVER_PORT=")) {
          String strWprt = split(iniData, "WEBSERVER_PORT=", "\r\n");
          strWprt.trim();
          WEB_PORT = strWprt.toInt();
        }

        if (instr(iniData, "WEBSERVER_IP=")) {
          String strwIp = split(iniData, "WEBSERVER_IP=", "\r\n");
          strwIp.trim();
          Server_IP.fromString(strwIp);
        }

        if (instr(iniData, "SUBNET_MASK=")) {
          String strsIp = split(iniData, "SUBNET_MASK=", "\r\n");
          strsIp.trim();
          Subnet_Mask.fromString(strsIp);
        }

        if (instr(iniData, "WIFI_SSID=")) {
          WIFI_SSID = split(iniData, "WIFI_SSID=", "\r\n");
          WIFI_SSID.trim();
        }

        if (instr(iniData, "WIFI_PASS=")) {
          WIFI_PASS = split(iniData, "WIFI_PASS=", "\r\n");
          WIFI_PASS.trim();
        }

        if (instr(iniData, "WIFI_HOST=")) {
          WIFI_HOSTNAME = split(iniData, "WIFI_HOST=", "\r\n");
          WIFI_HOSTNAME.trim();
        }

        if (instr(iniData, "CONWIFI=")) {
          String strcw = split(iniData, "CONWIFI=", "\r\n");
          strcw.trim();
          if (strcw.equals("true")) {
            connectWifi = true;
          } else {
            connectWifi = false;
          }
        }
        if (instr(iniData, "USBWAIT=")) {
          String strusw = split(iniData, "USBWAIT=", "\r\n");
          strusw.trim();
          USB_WAIT = strusw.toInt();
        }
      }
    } else {
      writeConfig();
    }
#endif
  }
  hasStarted = true;
}


void loadAP() {
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  WiFi.softAP(AP_SSID, AP_PASS);
  dnsServer.setTTL(30);
  dnsServer.setErrorReplyCode(DNSReplyCode::ServerFailure);
  dnsServer.start(53, "*", Server_IP);
}


void loadSTA() {
  WiFi.setHostname(WIFI_HOSTNAME.c_str());
  WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());
  if (WiFi.waitForConnectResult() != WL_CONNECTED) {
    loadAP();
  } else {
    IPAddress LAN_IP = WiFi.localIP();
    if (LAN_IP) {
      String mdnsHost = WIFI_HOSTNAME;
      mdnsHost.replace(".local", "");
      MDNS.begin(mdnsHost, LAN_IP);
      dnsServer.setTTL(30);
      dnsServer.setErrorReplyCode(DNSReplyCode::ServerFailure);
      dnsServer.start(53, "*", LAN_IP);
    }
  }
}


void setup() {

  startFileSystem();

  webServer.onNotFound(handleNotFound);
  webServer.on(
    "/upload.html", HTTP_POST, []() {
      webServer.sendHeader("Location", "/fileman.html");
      webServer.send(302, "text/html", "");
    },
    handleFileUpload);
  webServer.on("/upload.html", HTTP_GET, handleUploadHtml);
  webServer.on("/format.html", HTTP_GET, handleFormatHtml);
  webServer.on("/format.html", HTTP_POST, handleFormat);
  webServer.on("/fileman.html", HTTP_GET, handleFileMan);
  webServer.on("/info.html", HTTP_GET, handleInfo);
  webServer.on("/delete", HTTP_POST, handleDelete);
#if USECONFIG
  webServer.on("/config.html", HTTP_GET, handleConfigHtml);
  webServer.on("/config.html", HTTP_POST, handleConfig);
#endif
  webServer.on("/admin.html", HTTP_GET, handleAdminHtml);
  webServer.on("/reboot.html", HTTP_GET, handleRebootHtml);
  webServer.on("/reboot.html", HTTP_POST, handleReboot);
  webServer.begin(WEB_PORT);
  
  swebServer.getServer().setRSACert(new BearSSL::X509List(serverCert), new BearSSL::PrivateKey(serverKey));
  swebServer.getServer().setCache(&serverCache);
  webServer.on(
    "/updatelist.xml", HTTP_GET, []() {
      swebServer.send(200, "application/xml", updatelistData);
    });
  swebServer.onNotFound([]() {
  swebServer.sendHeader("Location", String("http://" + Server_IP.toString() + "/index.html" ), true);
  swebServer.send(301, "text/plain", "");
  });
  swebServer.begin();

}


void loop() {
  webServer.handleClient();
  swebServer.handleClient();
}


void setup1() {
  while (!hasStarted) {
    delay(1000);
  }
  if (connectWifi && WIFI_SSID.length() > 0 && WIFI_PASS.length() > 0) {
    loadSTA();
  } else {
    loadAP();
  }
}


void loop1() {
  dnsServer.processNextRequest();
  MDNS.update();
}
