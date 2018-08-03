# Arduino UNO proof-of-concept : securing IOT with Oauth and crypto

The goal is to provide a very simple example of communication between a device like a smartphone and
an Arduino UNO under Oauth2.0 control. Since the UNO model don't support HTTP request over TLS, I use AES128 to directly encrypt
the message layer.

![alt text](/images/schema.png)

### Dependencies

 [RestServer](https://github.com/tigerwill90/RestServer)

 [RestClient](https://github.com/csquared/arduino-restclient)

 [AesLib](https://github.com/DavyLandman/AESLib)

 [Base64](https://github.com/adamvr/arduino-base64)

 [ArduinoJson](https://github.com/bblanchon/ArduinoJson)


### Getting started

´´´´
Currently in developpement
´´´´

### TODO

* reduce memory usage
