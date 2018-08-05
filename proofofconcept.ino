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
//const uint8_t clientId[5] = {'0','1','2','3','4'};

// shared key between Oauth2.0 and IoT
const uint8_t clientSecret[16] = {'A','B','C','D','E','F','G','H','I','J','0','1','2','3','4','5'};

EthernetServer server(80);
RestServer rest(server);

IPAddress ip(192, 168, 192, 80);

void getWeather(char* query = "", char* body = "", char* bearer = "") {
  
  /**
   * Send the jwt to Oauth2.0 server via a post request
   * 
   * @improvement
   * For a correct RESTFul implementation, we would send a GET request
   * and attach jwt to Authorization header but the RESTclient has
   * very small header size.
   * 
   * @info
   * Proof of possession :
   */
  RestClient client = RestClient("192.168.192.29");
  String response = "";
  int statusCode = client.post("/keys",bearer,&response);
  switch(statusCode) {
    case 200:
      {
      /**
       * Receive json en parse response
       * 
       * @info
       * We convert the String response to a char array
       * in order to work with the ArduinoJson library.
       * Due to the very very limited amount of memory
       * available in the Arduino UNO, the json buffer
       * is very small.
       */
      char json[response.length() + 1];
      response.toCharArray(json,response.length() + 1);
      StaticJsonBuffer<50> jsonBuffer; // 50 for single mode, and 60 for cbc with IV
      JsonObject& input = jsonBuffer.parseObject(json);
      char* encrypted = input["key"];
      
      // clear the jsonbuffer
      jsonBuffer.clear();
  
      /**
       * Base 64 decoding
       * 
       * @info
       * To avoid non-ascii and all sort of special characters,
       * it's a common practice to encode in base64 an encrypted
       * cipher. The goal is to avoid non-HTTP-compatible characters
       */
      int input2Len = strlen(encrypted);
      int decodedLength = base64_dec_len(encrypted, input2Len);
      char key[decodedLength]; //don't work with number 16
      base64_decode(key, (uint8_t *)encrypted, input2Len);
    
      /**
       * Sharing key decryption
       * 
       * @algo : AES
       * @mode : ECB
       * @block : 128bits
       * @param : [16] uint8_t* secret, [16] uint8_t* plaintext
       * 
       * The Oauth2.0 Server send a sharing key to encrypt data
       * between the UNO and a device. Since no TLS is available
       * on the UNO, we need to register the IOT to the Oauth Server.
       * 
       * In the process of registration, the Oauth server generate a
       * strong "clientSecret". This secret is used for decrypt all
       * data from Oauth server.
       * 
       * Now the key can shared key can be safly transported over
       * HTTP request
       */
      aes128_dec_single(clientSecret, key);
      Serial.println(key);
    
      /**
       * The resource data 
       * 
       * It's just an example, should capture any digital/analog data
       * that need to be send to the client
       */
      char data[16] = {'B','A','C','H','E','L','O','R','O','A','U','T','H','2','.','0'};
      
      /**
       * Data encryption
       * 
       * @algo : AES
       * @mode : ECB
       * @block : 128bits
       * @param : [16] uint8_t* secret, [16] uint8_t* plaintext
       * 
       * We encrypt the data response with the shared key send
       * by the Oauth server. The client has exactly the same
       * key and can decrypt the data. Immediatly after the
       * encryption complete, the key is deleted
       */
      aes128_enc_single(key, data);
      memset(key, 0, sizeof(key));
  
      // base 64 encoding
      int inputLen = sizeof(data);
      int encodedLength = base64_enc_len(inputLen);
      char encoded[encodedLength];
      base64_encode(encoded, data, encodedLength);
      //encoded[strlen(encoded)-1] = "=";  
      
      //send response
      rest.addData("encoded", encoded);
      rest.sendResponse(OK,0);
      }
      break;
    
    case 401:
      rest.sendResponse(UNAUTHORIZED,0);
      break;
    default:
      rest.sendResponse(SERVER_ERROR,0);
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
  rest.onNotFound(notFound);
}

void loop() {
  rest.run();
}
