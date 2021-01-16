// ArduinoTuya
// Copyright Alex Cortelyou 2018
// MIT License

#include "ArduinoTuya.h"
#include <Arduino_CRC32.h>

void TuyaDevice::initGetRequest(JsonDocument &jsonRequest) {
  jsonRequest["gwId"] = _id;  //device id
  jsonRequest["devId"] = _id; //device id
  jsonRequest.createNestedObject("dps");
  jsonRequest["uid"] = _id; //device id
  jsonRequest["t"] = "1610771348";
}

void TuyaDevice::initSetRequest(JsonDocument &jsonRequest) {
  jsonRequest["t"] = 1610771348;
  jsonRequest["gwId"] = _id;  //device id
  jsonRequest["devId"] = _id; //device id
  jsonRequest.createNestedObject("dps");
  jsonRequest["uid"] = "";    //user id (required but value doesn't appear to be used)
}

String TuyaDevice::createPayload(JsonDocument &jsonRequest) {

  // Serialize json request
  String jsonString;
  serializeJson(jsonRequest, jsonString);
  DEBUG_PRINT("REQUEST  ");
  DEBUG_PRINTLN(jsonString);
  return jsonString;
}


String TuyaDevice::sendCommand(String &jsonString, byte command) {

  // Determine lengths and padding
  const int jsonLength = jsonString.length();
  const int cipherPadding = TUYA_BLOCK_LENGTH - jsonLength % TUYA_BLOCK_LENGTH;
  const int cipherLength = jsonLength + cipherPadding;

  // Allocate encrypted data buffer
  byte cipherData[cipherLength];

  memcpy(cipherData, jsonString.c_str(), jsonLength);
  memset(&cipherData[jsonLength], cipherPadding, cipherPadding);

  // AES ECB encrypt each block
  for (int i = 0; i < cipherLength; i += TUYA_BLOCK_LENGTH) {
    AES_ECB_encrypt(&_aes, &cipherData[i]);
  }

  const int payloadLength = cipherLength + (command == 10 ? 0 : 15);
  uint8_t payload[payloadLength];

  if (command != 10) {
    payload[0] = 51;
    payload[1] = 46;
    payload[2] = 51;
    payload[3] = NULL;
    payload[4] = NULL;
    payload[5] = NULL;
    payload[6] = NULL;
    payload[7] = NULL;
    payload[8] = NULL;
    payload[9] = NULL;
    payload[10] = NULL;
    payload[11] = NULL;
    payload[12] = NULL;
    payload[13] = NULL;
    payload[14] = NULL;
  }
  memcpy(payload + (command == 10 ? 0 : 15), cipherData, cipherLength);


  // Attempt to send command at least once
  int tries = 0;
  while (tries++ <= TUYA_RETRY_COUNT) {
    // Determine lengths and offsets
    const int bodyLength = payloadLength + TUYA_CRC_LENGTH + TUYA_SUFFIX_LENGTH;
    const int requestLength = 4 + 4 + 4 + 4 + payloadLength + 4 + 4;

    // Assemble request buffer
    byte request[requestLength];

    memcpy(request, prefix, 4);
    request[4] = (byte) ((tries >> 24) & 0xFF);
    request[5] = (byte) ((tries >> 16) & 0xFF);
    request[6] = (byte) ((tries >> 8) & 0xFF);
    request[7] = (byte) (tries & 0xFF);
    request[8] = (byte) ((command >> 24) & 0xFF);
    request[9] = (byte) ((command >> 16) & 0xFF);
    request[10] = (byte) ((command >> 8) & 0xFF);
    request[11] = (byte) (command & 0xFF);
    request[12] = (byte) ((bodyLength >> 24) & 0xFF);
    request[13] = (byte) ((bodyLength >> 16) & 0xFF);
    request[14] = (byte) ((bodyLength >> 8) & 0xFF);
    request[15] = (byte) (bodyLength & 0xFF);
    memcpy(&request[16], payload, payloadLength);

    Arduino_CRC32 crc32;
    uint32_t const crc32_res = crc32.calc(payload, 16 + payloadLength);

    request[16 + payloadLength + 0] = (byte)((crc32_res >> 24) & 0xFF);
    request[16 + payloadLength + 1] = (byte)((crc32_res >> 16) & 0xFF);
    request[16 + payloadLength + 2] = (byte)((crc32_res >> 8) & 0xFF);
    request[16 + payloadLength + 3] = (byte)(crc32_res & 0xFF);
    request[16 + payloadLength + 4] = (byte)0;
    request[16 + payloadLength + 5] = (byte)0;
    request[16 + payloadLength + 6] = (byte)170;
    request[16 + payloadLength + 7] = (byte)85;

    DEBUG_PRINTLN("payloadLength");
    DEBUG_PRINTLN(payloadLength);
//    for ( int i = 0; i < requestLength; i++ ) {
//      DEBUG_PRINTHEX(request[i]);
//    }
//    Serial.println();

    // Connect to device
    _client.setTimeout(TUYA_TIMEOUT);
    if (!_client.connect(_host, _port)) {
      DEBUG_PRINTLN("TUYA SOCKET ERROR");
      _error = TUYA_ERROR_SOCKET;
      delay(TUYA_RETRY_DELAY);
      continue;
    }

    // Wait for socket to be ready for write
    while (_client.connected() && _client.availableForWrite() < requestLength) delay(10);

    // Write request to device
    _client.write(request, requestLength);

    // Wait for socket to be ready for read
    while (_client.connected() && _client.available() < 11) delay(10);

    byte buffer[4096];
    _client.read(buffer, 4096);

//    for ( int i = 0; i < 200; i++ ) {
//      DEBUG_PRINTHEX(buffer[i]);
//    }
//    Serial.println();

    // Check prefix match
    if (memcmp(prefix, buffer, TUYA_PREFIX_LENGTH) != 0) {
      DEBUG_PRINTLN("TUYA PREFIX MISMATCH");
      _error = TUYA_ERROR_PREFIX;
      _client.stop();
      delay(TUYA_RETRY_DELAY);
      continue;
    }

    int idx = 4;
    int seq = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINTLN("SEQ");
    DEBUG_PRINTLN(seq);

    idx = 8;
    int cmd = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINTLN("cmd");
    DEBUG_PRINTLN(cmd);

    idx = 12;
    size_t length = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]) - 12;
    DEBUG_PRINTLN("length");
    DEBUG_PRINTLN(length);

    idx = 16;
    int code = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINTLN("code");
    DEBUG_PRINTLN(code);

    _client.stop();

    int offset = (cmd == 8) ? 15 : 0;
    idx = 20 + offset;
    length = length - offset;
    byte response[length + 1];
    memset(response, 0, length + 1);
    memcpy(response, buffer + idx, length);
    for (int i = 0; i < length; i += TUYA_BLOCK_LENGTH) {
      AES_ECB_decrypt(&_aes, &response[i]);
    }

    if (length > 0) {
      DEBUG_PRINT("RESPONSE ");
      DEBUG_PRINTLN((const char*)response);
    }

    _error = TUYA_OK;
    return String((const char*)response);
  }

  return String("");
}

tuya_error_t TuyaDevice::get() {

  // Allocate json objects
  StaticJsonDocument<512> jsonRequest;
  StaticJsonDocument<512> jsonResponse;

  // Build request
  initGetRequest(jsonRequest);

  String payload = createPayload(jsonRequest);

  String response = sendCommand(payload, 10);

  // Check for errors
  if (_error != TUYA_OK) return _error;

  // Deserialize json response
  auto error = deserializeJson(jsonResponse, response);
  if (error) return _error = TUYA_ERROR_PARSE;

  // Check response
  JsonVariant state = jsonResponse["dps"]["1"];
  if (state.isNull()) return _error = TUYA_ERROR_PARSE;

  _state = state.as<bool>() ? TUYA_ON : TUYA_OFF;
  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::set(bool state) {

  // Allocate json object
  StaticJsonDocument<512> jsonRequest;

  // Build request
  initSetRequest(jsonRequest);
  jsonRequest["dps"]["1"] = state;    //state

  String payload = createPayload(jsonRequest);

  String response = sendCommand(payload, 7);

  // Check for errors
  if (_error != TUYA_OK) return _error;
 
  _state = state ? TUYA_ON : TUYA_OFF;

  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::toggle() {
  return set(!_state);
}

tuya_error_t TuyaBulb::setColorRGB(byte r, byte g, byte b) {
  //https://gist.github.com/postspectacular/2a4a8db092011c6743a7
  float R = asFloat(r);
  float G = asFloat(g);
  float B = asFloat(b);
  float s = step(B, G);
  float px = mix(B, G, s);
  float py = mix(G, B, s);
  float pz = mix(-1.0, 0.0, s);
  float pw = mix(0.6666666, -0.3333333, s);
  s = step(px, R);
  float qx = mix(px, R, s);
  float qz = mix(pw, pz, s);
  float qw = mix(R, px, s);
  float d = qx - min(qw, py);
  float H = abs(qz + (qw - py) / (6.0 * d + 1e-10));
  float S = d / (qx + 1e-10);
  float V = qx;

  return setColorHSV(asByte(H), asByte(S), asByte(V));
}

tuya_error_t TuyaBulb::setColorHSV(byte h, byte s, byte v) {

  // Format color as hex string
  char hexColor[7];
  sprintf(hexColor, "%02x%02x%02x", h, s, v);

  // Allocate json object
  StaticJsonDocument<512> jsonRequest;

  // Build request
  initSetRequest(jsonRequest);
  jsonRequest["dps"]["5"] = hexColor;
  jsonRequest["dps"]["2"] = "colour";

  String payload = createPayload(jsonRequest);

  String response = sendCommand(payload, 7);

  return _error;
}

tuya_error_t TuyaBulb::setWhite(byte brightness, byte temp) {

  if (brightness < 25 || brightness > 255) {
    DEBUG_PRINTLN("BRIGHTNESS MUST BE BETWEEN 25 AND 255");
    return _error = TUYA_ERROR_ARGS;
  }

  // Allocate json object
  StaticJsonDocument<512> jsonRequest;

  // Build request
  initSetRequest(jsonRequest);
  jsonRequest["dps"]["2"] = "white";
  jsonRequest["dps"]["3"] = brightness;
  jsonRequest["dps"]["4"] = temp;

  String payload = createPayload(jsonRequest);

  String response = sendCommand(payload, 7);

  return _error;
}
