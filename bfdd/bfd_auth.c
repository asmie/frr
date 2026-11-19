// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD authentication digests (RFC 5880 Section 6.7).
 *
 * Keyed MD5 is not offered as an authentication type of its own; it is
 * the digest RFC 9986's optimized MD5 type signs state changes with.
 *
 * Copyright (c) 2026 Piotr Olszewski
 */

#include <zebra.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/evp.h>
#else
#include "lib/md5.h"
#endif

#include "bfd_auth.h"

#define BFD_AUTH_HDR_LEN    24 /* fixed control packet header */
#define BFD_AUTH_DIGEST_OFF (BFD_AUTH_HDR_LEN + 8)
#define BFD_AUTH_MD5_DIGEST 16

/*
 * The digest is taken over the whole packet with the key, zero padded,
 * in place of the digest itself. Feed the key in at that point instead of
 * copying the packet to put it there.
 *
 * A packet too short to hold the digest, or a key outside the 1 to 16
 * bytes RFC 5880 allows, is refused rather than truncated or padded into
 * some other secret. So is MD5 itself if the OpenSSL provider refuses it.
 */
static bool bfd_auth_md5(const uint8_t *pkt, size_t len, const char *key,
			 uint8_t digest[BFD_AUTH_MD5_DIGEST])
{
	uint8_t padded[BFD_AUTH_MD5_DIGEST] = {};
	size_t tail = BFD_AUTH_DIGEST_OFF + BFD_AUTH_MD5_DIGEST;
	size_t keylen = key ? strnlen(key, BFD_AUTH_MD5_KEY_MAX_LEN + 1) : 0;
	bool ok;

	if (len < tail || keylen == 0 || keylen > BFD_AUTH_MD5_KEY_MAX_LEN)
		return false;

	memcpy(padded, key, keylen);

#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int dlen = 0;

	ok = ctx && EVP_DigestInit_ex(ctx, EVP_md5(), NULL) &&
	     EVP_DigestUpdate(ctx, pkt, BFD_AUTH_DIGEST_OFF) &&
	     EVP_DigestUpdate(ctx, padded, sizeof(padded)) &&
	     EVP_DigestUpdate(ctx, pkt + tail, len - tail) &&
	     EVP_DigestFinal_ex(ctx, digest, &dlen) && dlen == BFD_AUTH_MD5_DIGEST;
	EVP_MD_CTX_free(ctx);
#else
	md5_ctxt ctx;

	md5_init(&ctx);
	md5_loop(&ctx, pkt, BFD_AUTH_DIGEST_OFF);
	md5_loop(&ctx, padded, sizeof(padded));
	md5_loop(&ctx, pkt + tail, len - tail);
	md5_pad(&ctx);
	md5_result(digest, &ctx);
	explicit_bzero(&ctx, sizeof(ctx));
	ok = true;
#endif

	explicit_bzero(padded, sizeof(padded));
	return ok;
}

bool bfd_auth_md5_sign(uint8_t *pkt, size_t len, const char *key)
{
	uint8_t digest[BFD_AUTH_MD5_DIGEST];

	/* Only point into the packet once it is known to be long enough. */
	if (!bfd_auth_md5(pkt, len, key, digest))
		return false;

	memcpy(pkt + BFD_AUTH_DIGEST_OFF, digest, sizeof(digest));
	return true;
}

bool bfd_auth_md5_verify(const uint8_t *pkt, size_t len, const char *key)
{
	uint8_t digest[BFD_AUTH_MD5_DIGEST];
	uint8_t diff = 0;
	size_t i;

	if (!bfd_auth_md5(pkt, len, key, digest))
		return false;

	/* Don't let the time taken tell how much of the digest matched. */
	for (i = 0; i < sizeof(digest); i++)
		diff |= digest[i] ^ pkt[BFD_AUTH_DIGEST_OFF + i];

	return diff == 0;
}
