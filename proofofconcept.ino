#include <Ethernet.h>
//#include <SPI.h>
#include <RestServer.h> //https://github.com/brunoluiz/arduino-restserver
#include <RestClient.h> //https://github.com/csquared/arduino-restclient
#include <AESLib.h> //https://github.com/DavyLandman/AESLib
#include <Base64.h> //https://github.com/adamvr/arduino-base64
#include <ArduinoJson.h> //https://github.com/bblanchon/ArduinoJson

#define DEBUG true

byte mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

//shared key
int clientId[5] = {'0','1','2','3','4'};
uint8_t clientSecret[16] = {'A','B','C','D','E','F','G','H','I','J','0','1','2','3','4','5'};
char key[16];

EthernetServer server(80);
RestServer rest(server);

IPAddress ip(192, 168, 192, 80);

void getConnexion(char* query = "", char* body = "", char* bearer = "") {
  
  // send jwt to Oauth2.0 server
  RestClient client = RestClient("jsonplaceholder.typicode.com");
  String response = "";
  //client.setHeader(bearer);
  int statusCode = client.get("/posts/1", &response);

  if (200 == statusCode) {
    // Receive json en parse response
    char json[] = "{\"key\": \"DZqq88ynCDS51jRahqz2/wAAAAAAAABH\"}";
    //char json[response.length()];
    //response.toCharArray(json,response.length());
    StaticJsonBuffer<50> jsonBuffer;
    JsonObject& root = jsonBuffer.parseObject(json);
  
    // decode b64 key
    char* encrypted = root["key"];
    int input2Len = strlen(encrypted);
    int decodedLength = base64_dec_len(encrypted, input2Len);
    char decoded[decodedLength];
    base64_decode(decoded, encrypted, input2Len);
  
    //decrypt key
    aes128_dec_single(clientSecret, decoded);
  
    //set global key
    strcpy(key,decoded);
  
    //send response
    rest.sendResponse(ACCEPTED,0);
  } else {
    rest.sendResponse(UNAUTHORIZED,0);
  }
}

void getWeather(char* query = "", char* body = "", char* bearer = "") {
  if (strlen(key) > 0) {
    //some sort of data to return
    char data[] = {'B','A','C','H','E','L','O','R','O','A','U','T','H','2','.','0'};
    
    //encrpyt
    aes128_enc_single(key, data);

    //reseting key
    memset(key, 0, sizeof(key));
  
    // base 64 encoding
    int inputLen = sizeof(data);
    int encodedLength = base64_enc_len(inputLen);
    char encoded[encodedLength];
    base64_encode(encoded, data, encodedLength);

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
