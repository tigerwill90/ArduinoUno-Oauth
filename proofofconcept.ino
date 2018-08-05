#include <Ethernet.h>
#include <SPI.h>
#include <RestServer.h> //https://github.com/brunoluiz/arduino-restserver
#include <RestClient.h> //https://github.com/csquared/arduino-restclient
#include <AESLib.h> //https://github.com/DavyLandman/AESLib
#include <Base64.h> //https://github.com/adamvr/arduino-base64
#include <ArduinoJson.h> //https://github.com/bblanchon/ArduinoJson
#include <avr/pgmspace.h>

#define DEBUG true

const byte mac[] PROGMEM = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

// client ID
const uint8_t clientId[5] PROGMEM = {'0','1','2','3','4'};

// shared key between Oauth2.0 and IoT
uint8_t clientSecret[16] = {'A','B','C','D','E','F','G','H','I','J','0','1','2','3','4','5'};
//uint8_t iv[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};

// shared key between device and IoT
// KdrxnE/VsUJ9NgDeDvlZXAAA
// test with 012345ABCDEFGHIJ
char key[16];

EthernetServer server(80);
RestServer rest(server);

IPAddress ip(192, 168, 192, 80);

void getConnexion(char* query = "", char* body = "", char* bearer = "") {
  
  //send jwt to Oauth2.0 server via a post request
  RestClient client = RestClient("192.168.192.29");
  String response = "";
  int statusCode = client.post("/keys",bearer,&response);
  //Serial.println(response);
  
  if (200 == statusCode) {
    
    // Receive json en parse response
    //char json[] = "{\"key\": \"KdrxnE/VsUJ9NgDeDvlZXAAA\"}";
    char json[response.length() + 1];
    response.toCharArray(json,response.length() + 1);
    StaticJsonBuffer<50> jsonBuffer; // 50 for single mode, and 60 for cbc with IV
    JsonObject& input = jsonBuffer.parseObject(json);
    
    // decode b64 key
    char* encrypted = input["key"];
    //Serial.println(encrypted);
    
    //char* iv = input["iv"];
    //Serial.println(iv);
    
    // clear the jsonbuffer
    jsonBuffer.clear();

    // decode the b64 key
    int input2Len = strlen(encrypted);
    int decodedLength = base64_dec_len(encrypted, input2Len);
    //Serial.println(decodedLength);
    char decoded[decodedLength]; //don't work with number 16
    base64_decode(decoded, encrypted, input2Len);
  
    //decrypt key
    aes128_dec_single(clientSecret, decoded);
    //aes128_cbc_dec(clientSecret, iv, decoded, 16); //too much memory usage
    Serial.println(decoded);
  
    //set global key
    strcpy(key,decoded);
  
    //send response
    rest.sendResponse(ACCEPTED,0);
  } else {
    rest.sendResponse(UNAUTHORIZED,0);
  }
}

void getWeather(char* query = "", char* body = "", char* bearer = "") {

  // No more memory but here normaly we check if the jwt is always valide
  
  if (strlen(key) > 0) {
    Serial.println(key);
    //some sort of data to return
    char encrypted[16] = {'B','A','C','H','E','L','O','R','O','A','U','T','H','2','.','0'};
    
    //encrpyt
    aes128_enc_single(key, encrypted);

    //reseting key
    memset(key, 0, sizeof(key));
  
    // base 64 encoding
    int inputLen = sizeof(encrypted);
    int encodedLength = base64_enc_len(inputLen);
    char encoded[encodedLength];
    base64_encode(encoded, encrypted, encodedLength);

    //attach and send data
    rest.addData("encoded", encoded);
    rest.sendResponse(OK,0);
  } else {
    rest.sendResponse(NO_CONTENT,0);
  }
}

void notFound(char* data = "") {
  rest.sendResponse(NOT_FOUND,0);
}

void setup() {
  // put your setup code here, to run once:
  #if DEBUG
    Serial.begin(9600); //opens serial port, sets data rate to 9600bps
  #endif
  pinMode(LED_BUILTIN, OUTPUT);

  Ethernet.begin(mac,ip);
  
  server.begin();
  Serial.println(Ethernet.localIP());

  rest.addRoute(GET, "/weather", getWeather);
  rest.addRoute(GET, "/connect", getConnexion);
  rest.onNotFound(notFound);
}

void loop() {
  rest.run();
}
