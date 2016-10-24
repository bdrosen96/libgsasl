/* session.c --- Data integrity/privacy protection of DIGEST-MD5.
 * Copyright (C) 2002-2012 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "session.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get gc_hmac_md5. */
#include <gc.h>

#define MD5LEN 16
#define SASL_INTEGRITY_PREFIX_LENGTH 4
#define MAC_DATA_LEN 4
#define MAC_HMAC_LEN 10
#define MAC_MSG_TYPE "\x00\x01"
#define MAC_MSG_TYPE_LEN 2
#define MAC_SEQNUM_LEN 4

static void slidebits(unsigned char *keybuf, unsigned char *inbuf)
{
    keybuf[0] = inbuf[0];
    keybuf[1] = (inbuf[0]<<7) | (inbuf[1]>>1);
    keybuf[2] = (inbuf[1]<<6) | (inbuf[2]>>2);
    keybuf[3] = (inbuf[2]<<5) | (inbuf[3]>>3);
    keybuf[4] = (inbuf[3]<<4) | (inbuf[4]>>4);
    keybuf[5] = (inbuf[4]<<3) | (inbuf[5]>>5);
    keybuf[6] = (inbuf[5]<<2) | (inbuf[6]>>6);
    keybuf[7] = (inbuf[6]<<1);
}

int digest_md5_crypt_init(_Gsasl_digest_md5_encrypt_state *state)
{

    if (state->cipher != 0) {
         char *my_key=NULL;
         char *peer_key=NULL;
         if (state->client) {
            my_key = state->kcc;
            peer_key = state->kcs;
         } else {
            my_key = state->kcs;
            peer_key = state->kcc;
         }
         if (state->cipher == DIGEST_MD5_CIPHER_RC4_56) {
            RC4_set_key(&state->rc4_key_encrypt, DIGEST_MD5_LENGTH, my_key);
            RC4_set_key(&state->rc4_key_decrypt, DIGEST_MD5_LENGTH, peer_key);
         } else if (state->cipher == DIGEST_MD5_CIPHER_RC4_40) {
            RC4_set_key(&state->rc4_key_encrypt, DIGEST_MD5_LENGTH, my_key);
            RC4_set_key(&state->rc4_key_decrypt, DIGEST_MD5_LENGTH, peer_key);
         } else if (state->cipher == DIGEST_MD5_CIPHER_RC4) {
            RC4_set_key(&state->rc4_key_encrypt, DIGEST_MD5_LENGTH, my_key);
            RC4_set_key(&state->rc4_key_decrypt, DIGEST_MD5_LENGTH, peer_key);
         } else if (state->cipher == DIGEST_MD5_CIPHER_3DES) {
            unsigned char keybuf[8];
            slidebits(keybuf, my_key);

            des_key_sched((des_cblock *) keybuf, state->keysched_encrypt);

            slidebits(keybuf, my_key + 7);

            des_key_sched((des_cblock *) keybuf, state->keysched2_encrypt);
            memcpy(state->ivec_encrypt, ((char *) my_key) + 8, 8);

            slidebits(keybuf, peer_key);
            des_key_sched((des_cblock *) keybuf, state->keysched_decrypt);

            slidebits(keybuf, peer_key + 7);

            des_key_sched((des_cblock *) keybuf, state->keysched2_decrypt);


            memcpy(state->ivec_decrypt, ((char *) peer_key) + 8, 8);


         } else if (state->cipher == DIGEST_MD5_CIPHER_DES) {

            unsigned char keybuf[8];
            slidebits(keybuf, my_key);

            des_key_sched((des_cblock *) keybuf, state->keysched_encrypt);

            memcpy(state->ivec_encrypt, ((char *) my_key) + 8, 8);

            slidebits(keybuf, peer_key);
            des_key_sched((des_cblock *) keybuf, state->keysched_decrypt);

            memcpy(state->ivec_decrypt, ((char *) peer_key) + 8, 8);
         }

    } else {
        return 0;
    }
}

int digest_md5_crypt_cleanup(_Gsasl_digest_md5_encrypt_state *state) {
    return 0;
}

void do_encrypt(_Gsasl_digest_md5_encrypt_state *state, const char* to_encrypt, int encrypt_length, char *encrypted) {
    if (state->cipher == DIGEST_MD5_CIPHER_RC4_56) {
        RC4(&state->rc4_key_encrypt, encrypt_length, to_encrypt, encrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_RC4_40) {
        RC4(&state->rc4_key_encrypt, encrypt_length, to_encrypt, encrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_RC4) {
        RC4(&state->rc4_key_encrypt, encrypt_length, to_encrypt, encrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_3DES) {
            des_ede2_cbc_encrypt((void *) to_encrypt,
			 (void *) encrypted,
			 encrypt_length,
			 state->keysched_encrypt,
			 state->keysched2_encrypt,
			 &state->ivec_encrypt,
			 DES_ENCRYPT);
     } else if (state->cipher == DIGEST_MD5_CIPHER_DES) {
            des_ncbc_encrypt((void *) to_encrypt,
                    (void *) encrypted,
                    encrypt_length,
                    state->keysched_encrypt,
                    &state->ivec_encrypt,
                    DES_ENCRYPT);
     }
}

void do_decrypt(_Gsasl_digest_md5_encrypt_state *state, const char* to_decrypt, int decrypt_length, char *decrypted) {
    if (state->cipher == DIGEST_MD5_CIPHER_RC4_56) {
        RC4(&state->rc4_key_decrypt, decrypt_length, to_decrypt, decrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_RC4_40) {
        RC4(&state->rc4_key_decrypt, decrypt_length, to_decrypt, decrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_RC4) {
        RC4(&state->rc4_key_decrypt, decrypt_length, to_decrypt, decrypted);
     } else if (state->cipher == DIGEST_MD5_CIPHER_3DES) {
        des_ede2_cbc_encrypt((void *) to_decrypt,
			 (void *) decrypted,
			 decrypt_length,
			 state->keysched_decrypt,
			 state->keysched2_decrypt,
			 &state->ivec_decrypt,
			 DES_DECRYPT);
     } else if (state->cipher == DIGEST_MD5_CIPHER_DES) {
        des_ncbc_encrypt((void *) to_decrypt,
                    (void *) decrypted,
                    decrypt_length,
                    state->keysched_decrypt,
                    &state->ivec_decrypt,
                    DES_DECRYPT);
     }
}


int
digest_md5_encode (_Gsasl_digest_md5_encrypt_state *state,
           const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   digest_md5_qop qop,
		   unsigned long sendseqnum, char key[DIGEST_MD5_LENGTH])
{
  int res;

  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      char pad[19]; // block size for rc4 is 1, and 8 for DES/3DES
      int padding = 0;
      int encrypt_length;
      size_t len;
      char *to_encrypt;
      char *encrypted;
      char *my_key=NULL;
      if (!state->cipher)
          return -1;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	    return -1;

      seqnumin[0] = (sendseqnum >> 24) & 0xFF;
      seqnumin[1] = (sendseqnum >> 16) & 0xFF;
      seqnumin[2] = (sendseqnum >> 8) & 0xFF;
      seqnumin[3] = sendseqnum & 0xFF;
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      if (state->client)
         my_key = state->kic;
      else
        my_key = state->kis;
      res = gc_hmac_md5 (my_key, MD5LEN,
			 seqnumin, MAC_SEQNUM_LEN + input_len, hash);
      free (seqnumin);
      if (res)
	    return -1;

      if (state->cipher == DIGEST_MD5_CIPHER_3DES || state->cipher == DIGEST_MD5_CIPHER_DES) {
        int i;
        padding = 8 - ((input_len+MAC_HMAC_LEN) % 8);
        for (i=0; i < padding; i++)
            pad[i] = padding;
      }
      to_encrypt = malloc(input_len+padding+MAC_HMAC_LEN);
      if (to_encrypt == NULL)
    	return -1;
      encrypted = malloc(input_len+padding+MAC_HMAC_LEN);
      if (encrypted == NULL) {
        free(to_encrypt);
    	return -1;
      }
      memcpy(to_encrypt, input, input_len);
      memcpy(to_encrypt+input_len, pad, padding);
      memcpy(to_encrypt+input_len+padding, hash, MAC_HMAC_LEN);
      encrypt_length = input_len+padding + MAC_HMAC_LEN;
      do_encrypt(state, to_encrypt, encrypt_length, encrypted);
      // Do encrypt
      free(to_encrypt);

	  *output_len = MAC_DATA_LEN + encrypt_length  +
	    MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;
	  *output = malloc (*output_len);
      if (!*output) {
        free(encrypted);
	    return -1;
      }
      len = MAC_DATA_LEN;
      memcpy (*output + len, encrypted, encrypt_length);
      free(encrypted);
      len += encrypt_length;
      memcpy (*output + len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
      len += MAC_MSG_TYPE_LEN;
      (*output + len)[0] = (sendseqnum >> 24) & 0xFF;
      (*output + len)[1] = (sendseqnum >> 16) & 0xFF;
      (*output + len)[2] = (sendseqnum >> 8) & 0xFF;
      (*output + len)[3] = sendseqnum & 0xFF;
      len += MAC_SEQNUM_LEN;
      (*output)[0] = ((len - MAC_DATA_LEN) >> 24) & 0xFF;
      (*output)[1] = ((len - MAC_DATA_LEN) >> 16) & 0xFF;
      (*output)[2] = ((len - MAC_DATA_LEN) >> 8) & 0xFF;
      (*output)[3] = (len - MAC_DATA_LEN) & 0xFF;
    }
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      size_t len;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	return -1;

      seqnumin[0] = (sendseqnum >> 24) & 0xFF;
      seqnumin[1] = (sendseqnum >> 16) & 0xFF;
      seqnumin[2] = (sendseqnum >> 8) & 0xFF;
      seqnumin[3] = sendseqnum & 0xFF;
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      res = gc_hmac_md5 (key, MD5LEN,
			 seqnumin, MAC_SEQNUM_LEN + input_len, hash);
      free (seqnumin);
      if (res)
	return -1;

      *output_len = MAC_DATA_LEN + input_len + MAC_HMAC_LEN +
	MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;
      *output = malloc (*output_len);
      if (!*output)
	return -1;

      len = MAC_DATA_LEN;
      memcpy (*output + len, input, input_len);
      len += input_len;
      memcpy (*output + len, hash, MAC_HMAC_LEN);
      len += MAC_HMAC_LEN;
      memcpy (*output + len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
      len += MAC_MSG_TYPE_LEN;
      (*output + len)[0] = (sendseqnum >> 24) & 0xFF;
      (*output + len)[1] = (sendseqnum >> 16) & 0xFF;
      (*output + len)[2] = (sendseqnum >> 8) & 0xFF;
      (*output + len)[3] = sendseqnum & 0xFF;
      len += MAC_SEQNUM_LEN;
      (*output)[0] = ((len - MAC_DATA_LEN) >> 24) & 0xFF;
      (*output)[1] = ((len - MAC_DATA_LEN) >> 16) & 0xFF;
      (*output)[2] = ((len - MAC_DATA_LEN) >> 8) & 0xFF;
      (*output)[3] = (len - MAC_DATA_LEN) & 0xFF;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return -1;
      memcpy (*output, input, input_len);
    }

  return 0;
}

#define C2I(buf) ((buf[3] & 0xFF) |		\
		  ((buf[2] & 0xFF) << 8) |	\
		  ((buf[1] & 0xFF) << 16) |	\
		  ((buf[0] & 0xFF) << 24))

int
digest_md5_decode (_Gsasl_digest_md5_encrypt_state *state,
           const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   digest_md5_qop qop,
		   unsigned long readseqnum, char key[DIGEST_MD5_LENGTH])
{
  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      unsigned long len;
      char tmpbuf[SASL_INTEGRITY_PREFIX_LENGTH];
      char msgType[MAC_MSG_TYPE_LEN];
      char seqNum[MAC_SEQNUM_LEN];
      char originalHash[GC_MD5_DIGEST_SIZE];
      char *encrypted;
      char *decrypted;
      int encrypted_length;
      int res;
      char *my_key=NULL;
      if (!state->cipher)
          return -1;

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH)
    	return -2;

      len = C2I (input);

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH + len)
	    return -2;

      if (state->client)
         my_key = state->kis;
      else
         my_key = state->kic;
      memcpy(msgType, input+input_len-MAC_SEQNUM_LEN-MAC_MSG_TYPE_LEN, MAC_MSG_TYPE_LEN);
      memcpy(seqNum, input+input_len-MAC_SEQNUM_LEN, MAC_SEQNUM_LEN);

      encrypted_length = input_len - MAC_MSG_TYPE_LEN - MAC_SEQNUM_LEN - MAC_DATA_LEN;
      encrypted = malloc(encrypted_length);
      if (encrypted == NULL)
        return -1;
      decrypted = malloc(encrypted_length);
      if (decrypted == NULL) {
        free(encrypted);
        return -1;
      }
      memcpy(encrypted, input+MAC_DATA_LEN, encrypted_length);

      do_decrypt(state, encrypted, encrypted_length, decrypted);
      free(encrypted);
      memcpy(originalHash, decrypted+encrypted_length-MAC_HMAC_LEN, MAC_HMAC_LEN);
      encrypted_length -= MAC_HMAC_LEN;
      if (state->cipher == DIGEST_MD5_CIPHER_3DES || state->cipher == DIGEST_MD5_CIPHER_DES) {
        encrypted_length -= decrypted[encrypted_length-1];
      }

      seqnumin = malloc (MAC_SEQNUM_LEN + encrypted_length);
      if (seqnumin == NULL) {
        free(decrypted);
	    return -1;
      }
      tmpbuf[0] = (readseqnum >> 24) & 0xFF;
      tmpbuf[1] = (readseqnum >> 16) & 0xFF;
      tmpbuf[2] = (readseqnum >> 8) & 0xFF;
      tmpbuf[3] = readseqnum & 0xFF;

      memcpy (seqnumin, tmpbuf, MAC_SEQNUM_LEN);
      memcpy (seqnumin + MAC_SEQNUM_LEN,
	      decrypted, encrypted_length);

      res = gc_hmac_md5 (my_key, MD5LEN, seqnumin, MAC_SEQNUM_LEN + encrypted_length, hash);
      free (seqnumin);
      if (res) {
        free(decrypted);
	    return -1;
      }
      if (memcmp(hash, originalHash, MAC_HMAC_LEN) == 0
	  && memcmp (MAC_MSG_TYPE,
		     msgType,
		     MAC_MSG_TYPE_LEN) == 0
	  && memcmp (tmpbuf, seqNum,
		     MAC_SEQNUM_LEN) == 0)
	{
	  *output_len = encrypted_length;
	  *output = malloc (*output_len);
	  if (!*output) {
	    free(decrypted);
	    return -1;
	  }
	  memcpy (*output, decrypted, encrypted_length);
	}
    else {
        free(decrypted);
	    return -1;
	 }
    }
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      unsigned long len;
      char tmpbuf[SASL_INTEGRITY_PREFIX_LENGTH];
      int res;

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH)
	return -2;

      len = C2I (input);

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH + len)
	return -2;

      len -= MAC_HMAC_LEN + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      seqnumin = malloc (SASL_INTEGRITY_PREFIX_LENGTH + len);
      if (seqnumin == NULL)
	return -1;

      tmpbuf[0] = (readseqnum >> 24) & 0xFF;
      tmpbuf[1] = (readseqnum >> 16) & 0xFF;
      tmpbuf[2] = (readseqnum >> 8) & 0xFF;
      tmpbuf[3] = readseqnum & 0xFF;

      memcpy (seqnumin, tmpbuf, SASL_INTEGRITY_PREFIX_LENGTH);
      memcpy (seqnumin + SASL_INTEGRITY_PREFIX_LENGTH,
	      input + MAC_DATA_LEN, len);

      res = gc_hmac_md5 (key, MD5LEN, seqnumin, MAC_SEQNUM_LEN + len, hash);
      free (seqnumin);
      if (res)
	return -1;

      if (memcmp
	  (hash,
	   input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN -
	   MAC_HMAC_LEN, MAC_HMAC_LEN) == 0
	  && memcmp (MAC_MSG_TYPE,
		     input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN,
		     MAC_MSG_TYPE_LEN) == 0
	  && memcmp (tmpbuf, input + input_len - MAC_SEQNUM_LEN,
		     MAC_SEQNUM_LEN) == 0)
	{
	  *output_len = len;
	  *output = malloc (*output_len);
	  if (!*output)
	    return -1;
	  memcpy (*output, input + MAC_DATA_LEN, len);
	}
      else
	return -1;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return -1;
      memcpy (*output, input, input_len);
    }

  return 0;
}
