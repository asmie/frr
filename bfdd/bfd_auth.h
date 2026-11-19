// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Piotr Olszewski */
#ifndef _BFDD_AUTH_H
#define _BFDD_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * RFC 5880 Section 6.7.3, keyed MD5: type, length, key ID, reserved,
 * sequence number and a 16 byte digest. The section always has this
 * length, so an authenticated packet is 48 bytes.
 */
#define BFD_AUTH_MD5_LEN	 24
#define BFD_AUTH_MD5_KEY_MAX_LEN 16

/*
 * Write the digest of a packet carrying a keyed MD5 section. The packet
 * must be complete apart from the digest field, whose contents are
 * ignored. Fails, writing nothing, for a packet too short to hold the
 * section, a key that is empty or longer than 16 bytes, or when the
 * OpenSSL provider refuses MD5.
 */
bool bfd_auth_md5_sign(uint8_t *pkt, size_t len, const char *key);

/*
 * Check the digest of a received packet carrying a keyed MD5 section.
 * A packet too short to hold one, or an unusable key, does not verify.
 */
bool bfd_auth_md5_verify(const uint8_t *pkt, size_t len, const char *key);

/*
 * RFC 5880 Section 6.7.3/6.7.4: once a sequence number is known, the next
 * must lie within bfd.RcvAuthSeq to bfd.RcvAuthSeq + 3 * Detect Mult, one
 * past that for the meticulous variants, in circular 32 bit space.
 */
static inline bool bfd_auth_seq_in_window(uint32_t last, uint32_t seq, bool meticulous,
					  uint8_t detect_mult)
{
	uint32_t distance = seq - last;

	return distance >= (meticulous ? 1U : 0U) && distance <= 3U * detect_mult;
}

#endif /* _BFDD_AUTH_H */
