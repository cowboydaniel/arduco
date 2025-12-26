/*

   ____  __  __  ____  _  _  _____       ___  _____  ____  _  _ 
  (  _ \(  )(  )(_  _)( \( )(  _  )___  / __)(  _  )(_  _)( \( )
   )(_) ))(__)(  _)(_  )  (  )(_)((___)( (__  )(_)(  _)(_  )  ( 
  (____/(______)(____)(_)\_)(_____)     \___)(_____)(____)(_)\_)
  Official code for Arduino boards (and relatives)   version 4.3
  
  Duino-Coin Team & Community 2019-2024 © MIT Licensed
  https://duinocoin.com
  https://github.com/revoxhere/duino-coin
  If you don't know where to start, visit official website and navigate to
  the Getting Started page. Have fun mining!
*/

/* For microcontrollers with low memory change that to -Os in all files,
for default settings use -O0. -O may be a good tradeoff between both */
#pragma GCC optimize ("Ofast")
#pragma GCC optimize ("unroll-loops")
/* For microcontrollers with custom LED pins, adjust the line below */
#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif
#define SEP_TOKEN ","
#define END_TOKEN "\n"
#ifndef DUCO_SERIAL_BAUD
#define DUCO_SERIAL_BAUD 500000
#endif
/* For 8-bit microcontrollers we should use 16 bit variables since the
difficulty is low, for all the other cases should be 32 bits. */
#if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
typedef uint32_t uintDiff;
#else
typedef uint32_t uintDiff;
#endif
// Arduino identifier library - https://github.com/ricaun
#include "uniqueID.h"

#include "duco_hash.h"

String get_DUCOID() {
  String ID = "DUCOID";
  char buff[4];
  for (size_t i = 0; i < 8; i++) {
    sprintf(buff, "%02X", (uint8_t)UniqueID8[i]);
    ID += buff;
  }
  return ID;
}

String DUCOID = "";

void print_startup_info() {
  Serial.print(F("Arch: "));
  #if defined(ARDUINO_ARCH_RENESAS)
    Serial.print(F("RENESAS/Cortex-M4F"));
  #elif defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
    Serial.print(F("AVR"));
  #else
    Serial.print(F("Generic"));
  #endif

  Serial.print(F(" | F_CPU: "));
  Serial.print(F_CPU / 1000000);
  Serial.println(F(" MHz"));
}

void setup() {
  // Prepare built-in led pin as output
  pinMode(LED_BUILTIN, OUTPUT);
  DUCOID = get_DUCOID();
  // Open serial port
  Serial.begin(DUCO_SERIAL_BAUD);
  Serial.setTimeout(10000);
  while (!Serial)
    ;  // For Arduino Leonardo or any board with the ATmega32U4
  Serial.flush();

  print_startup_info();
}

void lowercase_hex_to_bytes(char const * hexDigest, uint8_t * rawDigest) {
  for (uint8_t i = 0, j = 0; j < SHA1_HASH_LEN; i += 2, j += 1) {
    uint8_t x = hexDigest[i];
    uint8_t b = x >> 6;
    uint8_t r = ((x & 0xf) | (b << 3)) + b;

    x = hexDigest[i + 1];
    b = x >> 6;

    rawDigest[j] = (r << 4) | (((x & 0xf) | (b << 3)) + b);
  }
}

// DUCO-S1A hasher
uintDiff ducos1a(char const * prevBlockHash, char const * targetBlockHash, uintDiff difficulty) {
  #if defined(ARDUINO_ARCH_AVR) || defined(ARDUINO_ARCH_MEGAAVR)
    // If the difficulty is too high for AVR architecture then return 0
    if (difficulty > 655) return 0;
  #endif

  uint8_t target[SHA1_HASH_LEN];
  lowercase_hex_to_bytes(targetBlockHash, target);

  uintDiff const maxNonce = difficulty * 100 + 1;
  return ducos1a_mine(prevBlockHash, target, maxNonce);
}

static inline char * duco_fast_u32_to_str(uint32_t value, char * endPtr) {
  char * cursor = endPtr;
  *--cursor = 0;
  do {
    uint32_t const q = value / 10;
    *--cursor = char('0' + (value - q * 10));
    value = q;
  } while (value);
  return cursor;
}

uintDiff ducos1a_mine(char const * prevBlockHash, uint8_t const * target, uintDiff maxNonce) {
  static duco_hash_state_t hash;
  duco_hash_init(&hash, prevBlockHash);

  char nonceStr[11 + 1];
  char * const bufferEnd = nonceStr + sizeof(nonceStr);

  for (uintDiff nonce = 0; nonce < maxNonce; nonce++) {
    char * noncePtr = duco_fast_u32_to_str(nonce, bufferEnd);

    uint8_t const * hash_bytes = duco_hash_try_nonce(&hash, noncePtr);
    if (hash_bytes[0] == target[0] &&
        hash_bytes[1] == target[1] &&
        hash_bytes[2] == target[2] &&
        hash_bytes[3] == target[3] &&
        hash_bytes[4] == target[4] &&
        hash_bytes[5] == target[5] &&
        hash_bytes[6] == target[6] &&
        hash_bytes[7] == target[7] &&
        hash_bytes[8] == target[8] &&
        hash_bytes[9] == target[9] &&
        hash_bytes[10] == target[10] &&
        hash_bytes[11] == target[11] &&
        hash_bytes[12] == target[12] &&
        hash_bytes[13] == target[13] &&
        hash_bytes[14] == target[14] &&
        hash_bytes[15] == target[15] &&
        hash_bytes[16] == target[16] &&
        hash_bytes[17] == target[17] &&
        hash_bytes[18] == target[18] &&
        hash_bytes[19] == target[19]) {
      return nonce;
    }
  }

  return 0;
}

void loop() {
  // Wait for serial data
  if (Serial.available() <= 0) {
    return;
  }

  // Reserve 1 extra byte for comma separator (and later zero)
  char lastBlockHash[40 + 1];
  char newBlockHash[40 + 1];

  // Read last block hash
  if (Serial.readBytesUntil(',', lastBlockHash, 41) != 40) {
    return;
  }
  lastBlockHash[40] = 0;

  // Read expected hash
  if (Serial.readBytesUntil(',', newBlockHash, 41) != 40) {
    return;
  }
  newBlockHash[40] = 0;

  // Read difficulty
  uintDiff difficulty = strtoul(Serial.readStringUntil(',').c_str(), NULL, 10);
  // Clearing the receive buffer reading one job.
  while (Serial.available()) Serial.read();
  // Turn off the built-in led
  #if defined(ARDUINO_ARCH_AVR)
      PORTB = PORTB | B00100000;
  #else
      digitalWrite(LED_BUILTIN, LOW);
  #endif

  // Start time measurement
  uint32_t startTime = micros();

  // Call DUCO-S1A hasher
  uintDiff ducos1result = ducos1a(lastBlockHash, newBlockHash, difficulty);

  // Calculate elapsed time
  uint32_t elapsedTime = micros() - startTime;

  // Turn on the built-in led
  #if defined(ARDUINO_ARCH_AVR)
      PORTB = PORTB & B11011111;
  #else
      digitalWrite(LED_BUILTIN, HIGH);
  #endif

  // Clearing the receive buffer before sending the result.
  while (Serial.available()) Serial.read();

  // Send result back to the program with share time
  Serial.print(String(ducos1result, 2) 
               + SEP_TOKEN
               + String(elapsedTime, 2) 
               + SEP_TOKEN
               + String(DUCOID) 
               + END_TOKEN);
}
