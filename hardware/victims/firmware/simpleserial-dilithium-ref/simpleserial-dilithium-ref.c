/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "simpleserial-dilithium-ref.h"

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "simpleserial.h"

#include "dilithium/ref/api.h"
#include "dilithium/ref/params.h"
#include "dilithium/ref/randombytes.h"


uint8_t alg = DILITHIUM_MODE;
uint8_t secret_key[pqcrystals_dilithium5_SECRETKEYBYTES + 10] = DEFAULT_SECRET_KEY ;
uint16_t secret_key_length = 0;

uint8_t seed[MAX_PAYLOAD_LENGTH];
uint8_t seed_length = 0;

// used in sign function
uint8_t sig[CRYPTO_BYTES];
size_t siglen;

#define ASSERT(cond, msg) do \
{ \
  if (!(cond)) { \
    simpleserial_put('a', sizeof(msg) - 1, (msg)); \
    return ASSERT_FAILED; \
  } \
} while (0)

uint8_t get_key(uint8_t* k, uint8_t len)
{
	// Load key here
	return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
	/**********************************
	* Start user-specific code here. */
	trigger_high();

	//16 hex bytes held in 'pt' were sent
	//from the computer. Store your response
	//back into 'pt', which will send 16 bytes
	//back to computer. Can ignore of course if
	//not needed

	trigger_low();
	/* End user-specific code here. *
	********************************/
	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
	// Reset key here if needed
	return 0x00;
}

uint16_t get_key_length(uint8_t algorithm) {
  switch (algorithm) {
    case 2:
      return pqcrystals_dilithium2_SECRETKEYBYTES;
    case 3:
      return pqcrystals_dilithium3_SECRETKEYBYTES;
    case 5:
      return pqcrystals_dilithium5_SECRETKEYBYTES;
  }
  return 0;
}

uint16_t get_sig_length(uint8_t algorithm) {
  switch (algorithm) {
    case 2:
      return 2420;
    case 3:
      return 3293;
    case 5:
      return 4595;
  }
  return 0;
}

uint8_t set_key(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
  ASSERT(cmd == CMD_SET_KEY, "set_key: invalid cmd");
  ASSERT(alg != 0, "set_key: alg not specified");

  uint16_t key_length = get_key_length(alg);
  uint8_t last_scmd = key_length / MAX_PAYLOAD_LENGTH;
  uint8_t does_divide = !(key_length % MAX_PAYLOAD_LENGTH);
  if (does_divide) {
    last_scmd++;
  }
  ASSERT(scmd <= last_scmd, "set_key: scmd out of range");
  if (does_divide || scmd < last_scmd) {
    ASSERT(len == MAX_PAYLOAD_LENGTH, "set_key: invalid length");
  } else if (scmd == last_scmd) {
    ASSERT(len == key_length % MAX_PAYLOAD_LENGTH, "set_key: last scmd has invalid length");
  }
  memcpy(secret_key + MAX_PAYLOAD_LENGTH * scmd, buf, len);
  simpleserial_put('r', sizeof("ok") - 1, "ok");
  return 0x00;
}

uint8_t set_seed(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
  uint8_t ok_msg[13 + MAX_PAYLOAD_LENGTH + 1] = "set_seed ok: ";
  ASSERT(cmd == CMD_SET_SEED, "set_seed: invalid cmd");
  ASSERT(scmd == 0, "set_seed: invalid scmd");
  ASSERT(len <= MAX_PAYLOAD_LENGTH, "set_seed: invalid len");
  memcpy(seed, buf, len);
  memcpy(ok_msg + 13, buf, len);
  simpleserial_put('r', 13 + len, ok_msg);
  pseudorandombytes_seed(buf, len);
  return 0x00;
}

uint8_t set_alg(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
//  uint8_t ok_msg[] = "set_alg ok: 0HelloHello";
  uint8_t ok_msg[] = "set_alg ok: 0HelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHelloHello";

  ASSERT(cmd == CMD_SET_ALG, "set_alg: invalid cmd");
  ASSERT(scmd == 0, "set_alg: invalid scmd");
  ASSERT(len == 1, "set_alg: invalid len");
  uint8_t new_alg = *buf;
  ASSERT(new_alg == 2 || new_alg == 3 || new_alg == 5, "invalid alg for set_alg");

  alg = new_alg;
  ok_msg[12] += new_alg;
  simpleserial_put('r', MAX_PAYLOAD_LENGTH, ok_msg);
  return 0x00;
}

uint8_t sign(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
  ASSERT(cmd == CMD_SIGN, "sign: invalid cmd");
  ASSERT(scmd == 0, "sign: invalid scmd");
  ASSERT(alg != 0, "sign: alg not set");
  ASSERT(alg == 2, "sign: alg has to be 2 as of now");

  int result = pqcrystals_dilithium2_ref_signature(sig, &siglen, buf, len, secret_key);

  ASSERT(siglen == pqcrystals_dilithium2_BYTES, "sign: signature has unexpected length");
  simpleserial_put('r', sizeof("sign ok") - 1, "sign ok");
  return result; // 0 == success
}

uint8_t get_sig(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
  size_t sig_len = get_sig_length(alg);
  size_t num_packets;
  size_t last_packet_len;

  if (sig_len % MAX_PAYLOAD_LENGTH) { // does not divide
    num_packets = sig_len / MAX_PAYLOAD_LENGTH + 1;
    last_packet_len = sig_len % MAX_PAYLOAD_LENGTH;
  } else { // does divide
    num_packets = sig_len / MAX_PAYLOAD_LENGTH;
    last_packet_len = MAX_PAYLOAD_LENGTH;
  }

  ASSERT(scmd < num_packets, "get_sig: scmd out of range"); // prevent buffer overflow

  if (scmd == num_packets - 1) { // last packet
    simpleserial_put('r', last_packet_len, sig + scmd * MAX_PAYLOAD_LENGTH);
    return 0x00;
  }
  // not last packet; but valid scmd as of previous assert
  simpleserial_put('r', MAX_PAYLOAD_LENGTH, sig + scmd * MAX_PAYLOAD_LENGTH);
  return 0x00;
}

int main(void)
{
  platform_init();
  init_uart();
  trigger_setup();

  simpleserial_init();
  simpleserial_addcmd(CMD_SET_ALG, 1, set_alg);
  simpleserial_addcmd(CMD_SET_SEED, MAX_PAYLOAD_LENGTH, set_seed);
  simpleserial_addcmd(CMD_SET_KEY, MAX_PAYLOAD_LENGTH, set_key);
  simpleserial_addcmd(CMD_SIGN, MAX_PAYLOAD_LENGTH, sign);
  simpleserial_addcmd(CMD_GET_SIG, MAX_PAYLOAD_LENGTH, get_sig);

  while(1)
    simpleserial_get();
}
