# Arduino UNO proof-of-concept : securing IOT with Oauth and crypto

The goal is to provide a very simple example of communication between a device like a smartphone and
an Arduino UNO under Oauth2.0 control. Since the UNO model don't support HTTP request over TLS, I use AES128 to directly encrypt
the message layer.

![alt text](/images/schema.png)

### Dependencies

 * [RestServer](https://github.com/tigerwill90/RestServer)
 * [RestClient](https://github.com/csquared/arduino-restclient)
 * [AesLib](https://github.com/DavyLandman/AESLib)
 * [Base64](https://github.com/adamvr/arduino-base64)
 * [ArduinoJson v5.13.2](https://github.com/bblanchon/ArduinoJson)
 * [MemoryFree](https://github.com/maniacbug/MemoryFree/tree/master/examples/FreeMemory)
 * [Arduino IDE](https://www.arduino.cc/en/main/software)

### Getting started

You need first to add all dependencies above.

```
git clone https://github.com/tigerwill90/ArduinoUno-Oauth.git
Open the sketch "proofofconcept.ino" in Arduino IDE
Select the right board and port
compile and upload the sketch
```

### Version
v0.6-dev
