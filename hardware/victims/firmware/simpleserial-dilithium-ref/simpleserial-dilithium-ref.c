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
#include "dilithium/ref/randombytes.h"

uint8_t alg = 3;
uint8_t secret_key[pqcrystals_dilithium5_SECRETKEYBYTES];
uint16_t secret_key_length = 0;

uint8_t seed[MAX_PAYLOAD_LENGTH];
uint8_t seed_length = 0;

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

uint16_t get_key_length(void) {
  switch (alg) {
    case 2:
      return pqcrystals_dilithium2_SECRETKEYBYTES;
    case 3:
      return pqcrystals_dilithium3_SECRETKEYBYTES;
    case 5:
      return pqcrystals_dilithium5_SECRETKEYBYTES;
  }
  return 0;
}

uint8_t set_key(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf) {
  ASSERT(cmd == CMD_SET_KEY, "set_key: invalid cmd");
  ASSERT(alg != 0, "set_key: alg not specified");

  uint16_t key_length = get_key_length();
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
  uint8_t ok_msg[] = "set_alg ok: 0";

  ASSERT(cmd == CMD_SET_ALG, "set_alg: invalid cmd");
  ASSERT(scmd == 0, "set_alg: invalid scmd");
  ASSERT(len == 1, "set_alg: invalid len");
  uint8_t new_alg = *buf;
  ASSERT(new_alg == 2 || new_alg == 3 || new_alg == 5, "invalid alg for set_alg");

  alg = new_alg;
  ok_msg[sizeof(ok_msg) - 2] += new_alg;
  simpleserial_put('r', sizeof(ok_msg) - 1, ok_msg);
  return 0x00;
}

int main(void)
{
    platform_init();
	init_uart();
	trigger_setup();

 	/* Uncomment this to get a HELLO message for debug */
	/*
	putch('h');
	putch('e');
	putch('l');
	putch('l');
	putch('o');
	putch('\n');
	*/

	simpleserial_init();
#if SS_VER != SS_VER_2_1
	simpleserial_addcmd('p', 16, get_pt);
	simpleserial_addcmd('k', 16, get_key);
	simpleserial_addcmd('x', 0, reset);
#else
    simpleserial_addcmd(CMD_SET_ALG, 1, set_alg);
    simpleserial_addcmd(CMD_SET_SEED, MAX_PAYLOAD_LENGTH, set_seed);

#endif
	while(1)
		simpleserial_get();
}
