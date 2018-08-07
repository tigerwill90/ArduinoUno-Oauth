/**
 * @author : SYLVAIN MULLER
 * @version : v0.3-dev
 * @date : 05.08.2018
 *
 * This file is part of Bachelor's degree
 * of High School of Management of Geneva (HEG)
 *
 * subject : Securing an IoT untrusted network with Oauth2.0 protocol
 */
#include <Ethernet.h>
#include <SPI.h>
#include <RestServer.h> //https://github.com/tigerwill90/RestServer
#include <RestClient.h> //https://github.com/csquared/arduino-restclient
#include <AESLib.h> //https://github.com/DavyLandman/AESLib
#include <Base64.h> //https://github.com/adamvr/arduino-base64
#include <ArduinoJson.h> //https://github.com/bblanchon/ArduinoJson
#include <avr/pgmspace.h>
#include <MemoryFree.h> //https://github.com/maniacbug/MemoryFree/tree/master/examples/FreeMemory

#define DEBUG true

const byte mac[] PROGMEM = {
  0x49, 0xBE, 0x09, 0xC7, 0x03, 0x5A
};

// shared key between authorization server and IoT
const uint8_t clientSecret[16] = {'a','b','c','d','e','f','!','h','i','j','0','1','2','3','4','5'};

EthernetServer server(80);
RestServer rest(server);

IPAddress ip(192, 168, 192, 80);

/**
 * @route : /protected
 * void(char* char* char*)
 *
 * @info
 * The goal of this function is to return
 * data provided by a connector to a TRUSTED
 * device. The data is super secret and
 * MUST BE encrypted with a SHARED KEY
 */
void getProtectedResource(const char* query = "", const char* body = "", const char* bearer = "") {

  /**
   * Send the jwt to authorization server via a post request
   *
   * @improvement
   * For a correct RESTFul implementation, we would send a GET request
   * and attach jwt to Authorization header but the RESTclient has
   * very small header size.
   *
   * Introspection :
   * link : https://tools.ietf.org/html/draft-ietf-oauth-introspection-11
   * The protected resource (Arduino UNO) can query the authorization server to
   * determine the validity of the token. At any time, the authorization server
   * can invalidate the access token and break connexion between device and
   * the protected resource. The protected SHOULD be authorized to query the
   * authorization server by submitting a clientId and a clientSecret. Whitout
   * TLS supprot, this last point is vulnerable to man-in-the-middle attack.
   *
   * Proof of possession : RFC 7800
   * link : https://tools.ietf.org/html/rfc7800
   *
   * Need to be developped
   *
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
      base64_decode(key, encrypted, input2Len);

      /**
       * Sharing key decryption
       *
       * @algo : AES
       * @mode : ECB
       * @block : 128bits
       * @param : [16] uint8_t* secret, [16] uint8_t* plaintext
       *
       * Why ECB mode shouldn't be used ? https://blog.filippo.io/the-ecb-penguin/
       *
       * The authorization server send a sharing key to encrypt data
       * between the protected resource and a device. Since no TLS is available
       * on the Arduino UNO, we need to register the IOT to the authorization server.
       *
       * In the process of registration, the authorization server generate a
       * strong "clientSecret". This secret is used for decrypt all
       * data from authorization server.
       *
       * Now the shared key can be safly transported over
       * HTTP request
       */
      aes128_dec_single(clientSecret, key);
      Serial.println(key);

      /**
       * The resource data
       *
       * It's just an example, should capture any digital/analog data
       * that need to be send to the client. Due to the very low amount
       * of memory available, the data should be len <= 16
       *
       * If needed, the data size is adjusted to the cipherblock with
       * padding. The method for padding byte is defined in ANSI X.923
       * of ISO/IEC 9797-1
       *
       * link : https://en.wikipedia.org/wiki/Padding_%28cryptography%29#Byte_padding
       */
      uint8_t data[16] = "BACHELOROAUTH2.0";
      if (strlen((const char*)data) < 16) {;
        uint8_t k = '0';
        uint8_t l = '0';
        for (int i = strlen((const char*)data); i < 15; i++) {
          k++;
          if (k > '9') {
            l++;
          }
          data[i] = '0';
        }
        if (k == '9') {
          data[14] = '1';
          data[15] = '0';
        } else if (k > '9') {
          data[14] = '1';
          data[15] = l;
        } else {
          k++;
          data[15] = k;
        }
      }

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
      aes128_enc_single(key, (void*)data);
      memset(key, 0, sizeof(key));

      // base 64 encoding
      int inputLen = sizeof(data);
      int encodedLength = base64_enc_len(inputLen);
      char encoded[encodedLength]; //base64 len should be 24
      base64_encode(encoded, (char *)data, encodedLength);

      /**
       * Maybe a memory leak or base64 encoding implementation auto pad to a 32 len array
       * We need to correct the encoded string with a -10 len troncat
       */
      encoded[strlen(encoded)-10] = 0;
      //Serial.println(encoded);

      //send response
      rest.addData("encoded", encoded);
      Serial.println(freeMemory());
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

void notFound(const char* data = "") {
  Serial.println(freeMemory());
  rest.sendResponse(NOT_FOUND,0);
}

void setup() {
  // put your setup code here, to run once:
  #if DEBUG
    Serial.begin(9600); //opens serial port, sets data rate to 9600bps
  #endif

  pinMode(LED_BUILTIN, OUTPUT);

  Ethernet.begin(mac, ip);

  server.begin();
  Serial.println(Ethernet.localIP());

  /**
   * 909 bytes available without calling RestServer
   * 569 bytes available without not found handler
   * 539 bytes available before route callback
   */

  rest.addRoute(GET, "/protected", getProtectedResource);
  rest.onNotFound(notFound);

  Serial.println(freeMemory());
}

void loop() {
  rest.run();
}
