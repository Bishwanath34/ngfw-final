/*
  AI‑NGFW Arduino Agent (concept demo)
  -----------------------------------
  Example of how a microcontroller (Arduino + WiFi) could integrate
  with the AI‑NGFW gateway.

  - Periodically calls https://<gateway-host>:4001/verify-chain
  - If the response contains `"ok":true`  -> LED = GREEN (logs intact)
  - If `"ok":false`                      -> LED = RED (tampering detected)

  This shows:
    * Hardware reading security state from the AI brain
    * Hardware can then drive relays, alarms, or physically cut links
*/

#include <SPI.h>
#include <WiFiNINA.h>      // or WiFi101 / WiFi.h depending on board
#include <WiFiSSLClient.h>

const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Gateway hostname + port
const char* GATEWAY_HOST = "192.168.1.10";  // or "my-laptop.local"
const int   GATEWAY_PORT = 4001;

// Simple LED pins (adjust to your board)
const int GREEN_LED_PIN = 5;
const int RED_LED_PIN   = 6;

// Interval between checks (ms)
const unsigned long CHECK_INTERVAL_MS = 5000;

WiFiSSLClient client;
unsigned long lastCheck = 0;

void setup() {
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, LOW);

  Serial.begin(115200);
  while (!Serial) { ; }

  Serial.println("AI‑NGFW Arduino Agent starting...");

  // Connect to Wi‑Fi
  Serial.print("Connecting to Wi‑Fi: ");
  Serial.println(WIFI_SSID);

  int status = WL_IDLE_STATUS;
  while (status != WL_CONNECTED) {
    status = WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    delay(3000);
  }

  Serial.println("Wi‑Fi connected.");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Accept self‑signed TLS certificate (not safe for production,
  // okay for demo).
  client.setInsecure();
}

bool checkGatewayIntegrity() {
  Serial.println("Checking AI‑NGFW log integrity...");

  if (!client.connect(GATEWAY_HOST, GATEWAY_PORT)) {
    Serial.println("Connection failed.");
    return false;
  }

  // Build HTTP GET request
  String req = String("GET /verify-chain HTTP/1.1\r\n") +
               "Host: " + GATEWAY_HOST + ":" + String(GATEWAY_PORT) + "\r\n" +
               "Connection: close\r\n\r\n";

  client.print(req);

  // Read the response into a buffer
  String response = "";
  unsigned long timeout = millis();
  while (client.connected() && millis() - timeout < 5000) {
    while (client.available()) {
      char c = client.read();
      response += c;
    }
  }

  client.stop();

  // Very simple check: look for `"ok":true` in the body
  int idxOkTrue = response.indexOf("\"ok\":true");
  int idxOkFalse = response.indexOf("\"ok\":false");

  Serial.println("Gateway response:");
  Serial.println(response);

  if (idxOkTrue != -1) {
    return true;
  } else if (idxOkFalse != -1) {
    return false;
  } else {
    // If we can't parse, assume NOT ok for safety
    return false;
  }
}

void loop() {
  unsigned long now = millis();
  if (now - lastCheck >= CHECK_INTERVAL_MS) {
    lastCheck = now;

    bool ok = checkGatewayIntegrity();

    if (ok) {
      digitalWrite(GREEN_LED_PIN, HIGH);
      digitalWrite(RED_LED_PIN, LOW);
      Serial.println("Logs verified: GREEN");
    } else {
      digitalWrite(GREEN_LED_PIN, LOW);
      digitalWrite(RED_LED_PIN, HIGH);
      Serial.println("Tampering / error detected: RED");
    }
  }

  // Other hardware logic here (relays, buzzer, etc.)
}
