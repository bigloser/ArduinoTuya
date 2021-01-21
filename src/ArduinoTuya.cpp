// ArduinoTuya
// Copyright Alex Cortelyou 2018
// MIT License

#include "ArduinoTuya.h"

String TuyaDevice::sendCommand(String &jsonString, byte command)
{
  const int jsonLength = jsonString.length();
  const int cipherPadding = TUYA_BLOCK_LENGTH - jsonLength % TUYA_BLOCK_LENGTH;
  const int cipherLength = jsonLength + cipherPadding;

  byte cipherData[cipherLength];
  memcpy(cipherData, jsonString.c_str(), jsonLength);
  memset(&cipherData[jsonLength], cipherPadding, cipherPadding);

  // AES ECB encrypt each block
  for (int i = 0; i < cipherLength; i += TUYA_BLOCK_LENGTH)
  {
    AES_ECB_encrypt(&_aes, &cipherData[i]);
  }

  const int payloadLength = cipherLength + (command == 10 ? 0 : 15);
  uint8_t payload[payloadLength];

  if (command != 10)
  {
    payload[0] = 51;
    payload[1] = 46;
    payload[2] = 51;
    memset(&payload[3], '\0', 12);
  }
  memcpy(&payload[command == 10 ? 0 : 15], cipherData, cipherLength);

  int tries = 0;
  while (tries++ <= TUYA_RETRY_COUNT)
  {
    const unsigned int bodyLength = payloadLength + TUYA_CRC_LENGTH + TUYA_SUFFIX_LENGTH;
    const unsigned int requestLength = TUYA_PREFIX_LENGTH + 3 * 4 + bodyLength;

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
    if (!_client.connect(_host, _port))
    {
      DEBUG_PRINTLN("TUYA SOCKET ERROR");
      _error = TUYA_ERROR_SOCKET;
      delay(TUYA_RETRY_DELAY);
      continue;
    }

    while (_client.connected() && _client.availableForWrite() < requestLength)
      delay(10);
    _client.write(request, requestLength);
    while (_client.connected() && _client.available() < 20)
      delay(10);

    byte buffer[20];
    _client.read(buffer, 20);

    //    for ( int i = 0; i < 200; i++ ) {
    //      DEBUG_PRINTHEX(buffer[i]);
    //    }
    //    Serial.println();

    if (memcmp(prefix, buffer, TUYA_PREFIX_LENGTH) != 0)
    {
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
    int length = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    length -= 12;
    DEBUG_PRINT("LENGTH: ");
    DEBUG_PRINTLN(length);

    idx = 16;
    int code = (buffer[idx] << 24) | (buffer[idx + 1] << 16) | (buffer[idx + 2] << 8) | (buffer[idx + 3]);
    DEBUG_PRINT("RETURN CODE: ");
    DEBUG_PRINTLN(code);

    String resp_string("");

    if (length > 0)
    {
      while (_client.connected() && _client.available() < length)
        delay(10);

      byte resp_buffer[length + 1];
      _client.read(resp_buffer, length);

      const int offset = (cmd == 8) ? 15 : 0;
      for (int i = offset; i < (length - offset); i += TUYA_BLOCK_LENGTH)
      {
        AES_ECB_decrypt(&_aes, &resp_buffer[i]);
      }

      byte response[length + 1 - offset];
      memcpy(response, resp_buffer + offset, length - offset);
      resp_string = String((const char *)response);
      DEBUG_PRINT("RESPONSE ");
      DEBUG_PRINTLN(resp_string);
    }
    else
    {
      DEBUG_PRINTLN("EMPTY RESPONSE");
    }

    _client.stop();

    _error = TUYA_OK;
    return resp_string;
  }

  return String("");
}

tuya_error_t TuyaDevice::get()
{
  StaticJsonDocument<512> jsonRequest;
  StaticJsonDocument<512> jsonResponse;
  initRequest(jsonRequest);
  String payload = createPayload(jsonRequest);
  String response = sendCommand(payload, 10);
  if (_error != TUYA_OK)
    return _error;
  auto error = deserializeJson(jsonResponse, response);
  if (error)
    return _error = TUYA_ERROR_PARSE;
  JsonVariant state = jsonResponse["dps"]["1"];
  if (state.isNull())
    return _error = TUYA_ERROR_PARSE;
  _state = state.as<bool>() ? TUYA_ON : TUYA_OFF;
  processResponse(jsonResponse);
  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::set(bool state)
{
  StaticJsonDocument<512> jsonRequest;
  StaticJsonDocument<512> jsonResponse;
  initRequest(jsonRequest);
  jsonRequest["dps"]["1"] = state;
  String payload = createPayload(jsonRequest);
  String response = sendCommand(payload, 7);
  if (_error != TUYA_OK)
    return _error;
  auto error = deserializeJson(jsonResponse, response);
  if (error)
    return _error = TUYA_ERROR_PARSE;
  _state = state ? TUYA_ON : TUYA_OFF;
  return _error = TUYA_OK;
}

tuya_error_t TuyaDevice::toggle()
{
  return set(!_state);
}

void TuyaDevice::processResponse(JsonDocument &jsonResponse)
{
}

void TuyaBulb::processResponse(JsonDocument &jsonResponse)
{
  _type = strcmp("white", jsonResponse["dps"]["2"]);
  _brightness = jsonResponse["dps"]["3"];
  _temp = jsonResponse["dps"]["4"];
}

tuya_error_t TuyaBulb::setColorRGB(byte r, byte g, byte b)
{
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

tuya_error_t TuyaBulb::setColorHSV(byte h, byte s, byte v)
{
  char hexColor[7];
  sprintf(hexColor, "%02x%02x%02x", h, s, v);
  StaticJsonDocument<512> jsonRequest;
  initRequest(jsonRequest);
  jsonRequest["dps"]["5"] = hexColor;
  jsonRequest["dps"]["2"] = "colour";
  String payload = createPayload(jsonRequest);
  String response = sendCommand(payload, 7);
  _type = 0;
  return _error;
}

tuya_error_t TuyaBulb::setWhite(byte brightness, byte temp)
{
  if (brightness < 25 || brightness > 255)
  {
    DEBUG_PRINTLN("BRIGHTNESS MUST BE BETWEEN 25 AND 255");
    return _error = TUYA_ERROR_ARGS;
  }

  if (_type != 1 || _brightness != brightness || _temp != temp)
  {
    StaticJsonDocument<512> jsonRequest;
    initRequest(jsonRequest);
    jsonRequest["dps"]["2"] = "white";
    jsonRequest["dps"]["3"] = brightness;
    jsonRequest["dps"]["4"] = temp;
    String payload = createPayload(jsonRequest);
    String response = sendCommand(payload, 7);
    _type = 1;
    _brightness = brightness;
    _temp = temp;
    return _error;
  }
  else
  {
    DEBUG_PRINTLN("COLOR/BRIGHTNESS/TEMPERATURE ALREADY SET, SKIPPING");
    return TUYA_OK;
  }
}

void TuyaDevice::initRequest(JsonDocument &jsonRequest)
{
  jsonRequest["gwId"] = _id;  //device id
  jsonRequest["devId"] = _id; //device id
  jsonRequest.createNestedObject("dps");
  jsonRequest["uid"] = _id; //device id
  jsonRequest["t"] = "1610771348";
}

String TuyaDevice::createPayload(JsonDocument &jsonRequest)
{
  String jsonString;
  serializeJson(jsonRequest, jsonString);
  DEBUG_PRINT("REQUEST  ");
  DEBUG_PRINTLN(jsonString);
  return jsonString;
}
