#include <Ethernet.h>
//#include <SPI.h>
#include <RestServer.h> //https://github.com/brunoluiz/arduino-restserver
#include <RestClient.h> //https://github.com/csquared/arduino-restclient
//#include <Arduino.h> 
#include <AESLib.h> //https://github.com/DavyLandman/AESLib
#include <Base64.h> //https://github.com/adamvr/arduino-base64
#include <ArduinoJson.h> //https://github.com/bblanchon/ArduinoJson
//#include <string.h>

#define DEBUG true

byte mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

//shared key
int clientId[5] = {'0','1','2','3','4'};
char key[16];

EthernetServer server(80);
RestServer rest(server);

IPAddress ip(192, 168, 192, 80);

void getConnexion(char* query = "", char* body = "", char* bearer = "") {

  uint8_t clientSecret[16] = {'A','B','C','D','E','F','G','H','I','J','0','1','2','3','4','5'};
  
  // send jwt to Oauth2.0 server
  RestClient client = RestClient("jsonplaceholder.typicode.com");
  String response = "";
  //client.setHeader(bearer);
  int statusCode = client.post("/posts",bearer, &response);
  Serial.println(statusCode);

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
    Serial.println(decoded);
  
    //set global key
    strcpy(key,decoded);
  
    //send response
    rest.sendResponse(ACCEPTED,"application/json",0);
  } else {
    rest.sendResponse(UNAUTHORIZED,"application/json",0);
  }
}

void getWeather(char* query = "", char* body = "", char* bearer = "") {
  rest.addData("key", key);
  rest.sendResponse(OK,"application/json",0);
}

void doDisconnexion(char* query = "", char* body = "", char* bearer = "") {
  memset(key, 0, sizeof(key));
  rest.sendResponse(NO_CONTENT,"application/json",0);
}

void notFound(char* data = "") {
  rest.addData("Not Found", data);
  rest.sendResponse(NOT_FOUND,"application/json",0);
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

  /*
  //uint8_t iv[16] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'};
  
  //char c[32] = {0x41,0x42,0x43,0x44,0x45 ,0x46,0x47,0x48 ,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x30,0x31,0x32,0x33,0x34,0x35};
  //uint8_t* key1 = (uint8_t *)c; // 16 bits keys casted from a char array, win
  // char + 1 => \O
  char data[17] = "ABCDEFGHIJ012345"; //16 chars == 16 bytes => char data[17] should be mod 16 => 16 + 1 || 32 + 1 || 48 + 1 etc..
  
  uint16_t dataLength = sizeof(data) - 1;
  //char data[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
  //uint16_t eLen = ((sizeof(data) - 1)|15)+1;
  Serial.print("Plain text : ");
  Serial.println(data);
  
  //aes128_cbc_enc(key1, iv, data, sizeof(data) - 1);
  //aes256_enc_multiple(key1, data, dataLength); // 256 bit without iv
  aes128_enc_single(clientSecret, data);
  // base 64 encoding
  int inputLen = sizeof(data);
  int encodedLength = base64_enc_len(inputLen);
  char encoded[encodedLength];
  base64_encode(encoded, data, encodedLength); 

  // encrypted char => non-ascii
  Serial.print("encrypted : ");
  Serial.println(data);
  // encoded encrypted => ascii
  Serial.print("encoded : ");
  Serial.println(encoded);

  //decode encrypted => non-ascii
  int input2Len = sizeof(encoded);
  int decodedLength = base64_dec_len(encoded, input2Len);
  char decoded[decodedLength];
  base64_decode(decoded, encoded, input2Len);
  Serial.print("decoded : ");
  Serial.println(decoded);
  //uint16_t dLen = ((sizeof(decoded) - 1)|15)+1; // modulo experession to find the nearest multiple of 16
  //Serial.println(dLen);

  //char decrypted[data];
  //strncpy(decrypted, data, (uint16_t)sizeof(data)); // copy encrypted data to decrypted variable
  
  uint8_t key2[32] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5'};
  //aes128_cbc_dec(key2, iv, decoded, sizeof(decoded) - 1);
  //aes256_dec_multiple(key2, decoded, dataLength); // 256 bit without iv, need to pass a length in request
  aes128_dec_single(clientSecret, decoded);
  Serial.print("decrypted : ");
  Serial.println(decoded);
  */
  

  rest.addRoute(GET, "/weather", getWeather);
  rest.addRoute(GET, "/connect", getConnexion);
  //rest.addRoute(DELETE, "/disconnect", doDisconnexion);
  rest.onNotFound(notFound);

  //RestClient client = RestClient("jsonplaceholder.typicode.com");
  //String response = "";
  //int statusCode = client.get("/todos/1", &response);
  //Serial.print("Status code from server: ");
  //Serial.println(statusCode);
  //Serial.print("Response body from server: ");
  //Serial.println(response);

}

void loop() {
  rest.run();
}
