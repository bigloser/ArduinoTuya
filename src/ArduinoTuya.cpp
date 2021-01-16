// ArduinoTuya
// Copyright Alex Cortelyou 2018
// MIT License

#include "ArduinoTuya.h"

String TuyaDevice::sendCommand(String &jsonString, byte command) {
  const int jsonLength = jsonString.length();
  const int cipherPadding = TUYA_BLOCK_LENGTH - jsonLength % TUYA_BLOCK_LENGTH;
  const int cipherLength = jsonLength + cipherPadding;

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
    memset(&payload[3], NULL, 12);
  }
  memcpy(&payload[command == 10 ? 0 : 15], cipherData, cipherLength);

  int tries = 0;
  while (tries++ <= TUYA_RETRY_COUNT) {
    const int bodyLength = payloadLength + TUYA_CRC_LENGTH + TUYA_SUFFIX_LENGTH;
    const int requestLength = TUYA_PREFIX_LENGTH + 3 * 4 + bodyLength;

    byte request[requestLength];

    memcpy(request, prefix, TUYA_PREFIX_LENGTH);
    cpyBEInt(tries, 4, request);
    cpyBEInt(command, 2 * 4, request);
    cpyBEInt(bodyLength, 3 * 4, request);
    memcpy(&request[TUYA_PREFIX_LENGTH + 3 * 4], payload, payloadLength);

    Arduino_CRC32 crc32;
    uint32_t const crc32_res = crc32.calc(payload, TUYA_PREFIX_LENGTH + 3 * 4 + payloadLength);
    cpyBEInt(crc32_res, TUYA_PREFIX_LENGTH + 3 * 4 + payloadLength, request);

    memcpy(&request[TUYA_PREFIX_LENGTH + 3 * 4 + payloadLength + TUYA_CRC_LENGTH], suffix, TUYA_SUFFIX_LENGTH);

    DEBUG_PRINT("PAYLOAD LENGTH: ");
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

    while (_client.connected() && _client.availableForWrite() < requestLength) delay(10);
    _client.write(request, requestLength);
    while (_client.connected() && _client.available() < 20) delay(10);

    byte buffer[4096];
    _client.read(buffer, 4096);

    //    for ( int i = 0; i < 200; i++ ) {
    //      DEBUG_PRINTHEX(buffer[i]);
    //    }
    //    Serial.println();

    if (memcmp(prefix, buffer, TUYA_PREFIX_LENGTH) != 0) {
      DEBUG_PRINTLN("TUYA PREFIX MISMATCH");
      _error = TUYA_ERROR_PREFIX;
      _client.stop();
      delay(TUYA_RETRY_DELAY);
      continue;
    }

    int idx = 4;
    int seq = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINT("SEQ: ");
    DEBUG_PRINTLN(seq);

    idx = 8;
    int cmd = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINT("CMD: ");
    DEBUG_PRINTLN(cmd);

    idx = 12;
    size_t length = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]) - 12;
    DEBUG_PRINT("LENGTH: ");
    DEBUG_PRINTLN(length);

    idx = 16;
    int code = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINT("RETURN CODE: ");
    DEBUG_PRINTLN(code);

    _client.stop();

    const int offset = (cmd == 8) ? 15 : 0;
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
  StaticJsonDocument<512> jsonRequest;
  StaticJsonDocument<512> jsonResponse;
  initRequest(jsonRequest);
  String payload = createPayload(jsonRequest);
  String response = sendCommand(payload, 10);
  if (_error != TUYA_OK) return _error;
  auto error = deserializeJson(jsonResponse, response);
  if (error) return _error = TUYA_ERROR_PARSE;
  JsonVariant state = jsonResponse["dps"]["1"];
  if (state.isNull()) return _error = TUYA_ERROR_PARSE;
  _state = state.as<bool>() ? TUYA_ON : TUYA_OFF;
  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::set(bool state) {
  StaticJsonDocument<512> jsonRequest;
  StaticJsonDocument<512> jsonResponse;
  initRequest(jsonRequest);
  jsonRequest["dps"]["1"] = state;
  String payload = createPayload(jsonRequest);
  String response = sendCommand(payload, 7);
  if (_error != TUYA_OK) return _error;
  auto error = deserializeJson(jsonResponse, response);
  if (error) return _error = TUYA_ERROR_PARSE;
  _state = state ? TUYA_ON : TUYA_OFF;
  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::toggle() {
  return set(!_state);
}

void TuyaDevice::initRequest(JsonDocument &jsonRequest) {
  jsonRequest["gwId"] = _id;  //device id
  jsonRequest["devId"] = _id; //device id
  jsonRequest.createNestedObject("dps");
  jsonRequest["uid"] = _id; //device id
  jsonRequest["t"] = "1610771348";
}

String TuyaDevice::createPayload(JsonDocument &jsonRequest) {
  String jsonString;
  serializeJson(jsonRequest, jsonString);
  DEBUG_PRINT("REQUEST  ");
  DEBUG_PRINTLN(jsonString);
  return jsonString;
}
