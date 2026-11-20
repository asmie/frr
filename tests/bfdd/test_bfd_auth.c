// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD keyed MD5 digest (RFC 5880 Section 6.7.3), which RFC 9986 uses for
 * the more computationally intensive format of its optimized MD5 type.
 *
 * The expected digests were computed independently with Python's hashlib:
 * MD5 over the 48 byte packet with the key, zero padded to 16 bytes, in
 * the Auth Key/Digest field.
 *
 * Copyright (c) 2026 Piotr Olszewski
 */
#include <zebra.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/evp.h>
#endif

#include "bfdd/bfd_auth.h"

#define PKT_LEN	   48
#define DIGEST_OFF 32

/* Up, A bit, mult 3, keyed MD5, key ID 7, sequence 0x01020304. */
static const uint8_t keyed[PKT_LEN] = {
	0x20, 0xc4, 0x03, 0x30, 0x40, 0x02, 0xd1, 0x5c, 0x0b, 0xfd, 0x5e, 0xed,
	0x00, 0x04, 0x93, 0xe0, 0x00, 0x04, 0x93, 0xe0, 0x00, 0x00, 0xc3, 0x50,
	0x02, 0x18, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x9a, 0xd3, 0x84, 0x79,
	0xf6, 0x7c, 0xf7, 0x25, 0x95, 0xbd, 0x6d, 0x89, 0xe9, 0x80, 0xf2, 0xc7,
};
#define KEYED_KEY "frrbfdkey"

/* Meticulous, key ID 255, sequence 0xfffffffe, a key filling all 16 bytes. */
static const uint8_t meticulous[PKT_LEN] = {
	0x20, 0xc4, 0x03, 0x30, 0x40, 0x02, 0xd1, 0x5c, 0x0b, 0xfd, 0x5e, 0xed,
	0x00, 0x04, 0x93, 0xe0, 0x00, 0x04, 0x93, 0xe0, 0x00, 0x00, 0xc3, 0x50,
	0x03, 0x18, 0xff, 0x00, 0xff, 0xff, 0xff, 0xfe, 0x9d, 0x40, 0x55, 0xcc,
	0x83, 0xc8, 0xbb, 0x93, 0xc5, 0x3d, 0xfe, 0x0f, 0x6d, 0x7d, 0xaf, 0x4a,
};
#define METICULOUS_KEY "sixteenbyteskey1"

static void test_sign(const uint8_t *expected, const char *key)
{
	uint8_t pkt[PKT_LEN];

	/* Whatever the digest field held before must not matter. */
	memcpy(pkt, expected, PKT_LEN);
	memset(pkt + DIGEST_OFF, 0xa5, PKT_LEN - DIGEST_OFF);
	assert(bfd_auth_md5_sign(pkt, PKT_LEN, key));
	assert(memcmp(pkt, expected, PKT_LEN) == 0);
}

static void test_digests(void)
{
	test_sign(keyed, KEYED_KEY);
	test_sign(meticulous, METICULOUS_KEY);
	assert(bfd_auth_md5_verify(keyed, PKT_LEN, KEYED_KEY));
	assert(bfd_auth_md5_verify(meticulous, PKT_LEN, METICULOUS_KEY));
	printf("keyed MD5 digests: ok\n");
}

static void test_verify_failures(void)
{
	uint8_t pkt[PKT_LEN];
	size_t i;

	/* Every byte is covered, the digest itself included. */
	for (i = 0; i < PKT_LEN; i++) {
		memcpy(pkt, keyed, PKT_LEN);
		pkt[i] ^= 0x01;
		assert(!bfd_auth_md5_verify(pkt, PKT_LEN, KEYED_KEY));
	}

	/* Another key, and one that only differs from it by the padding. */
	assert(!bfd_auth_md5_verify(keyed, PKT_LEN, "frrbfdkez"));
	assert(!bfd_auth_md5_verify(keyed, PKT_LEN, "frrbfdke"));

	/* Too short to hold the digest: refused, not read past. */
	assert(!bfd_auth_md5_verify(keyed, PKT_LEN - 1, KEYED_KEY));
	printf("verification failures: ok\n");
}

/* A bare header, so that nothing past it may be touched. */
static void test_short_packet(void)
{
	uint8_t hdr[24];

	memcpy(hdr, keyed, sizeof(hdr));
	assert(!bfd_auth_md5_verify(hdr, sizeof(hdr), KEYED_KEY));
	assert(!bfd_auth_md5_sign(hdr, sizeof(hdr), KEYED_KEY));
	assert(memcmp(hdr, keyed, sizeof(hdr)) == 0);
	printf("short packet: ok\n");
}

static void test_key_length(void)
{
	uint8_t pkt[PKT_LEN];

	/*
	 * Longer than 16 bytes would otherwise be cut to the 16 the packet
	 * was signed with, and empty would be an all zero key.
	 */
	assert(!bfd_auth_md5_verify(meticulous, PKT_LEN, METICULOUS_KEY "x"));
	assert(!bfd_auth_md5_verify(meticulous, PKT_LEN, ""));
	assert(!bfd_auth_md5_verify(meticulous, PKT_LEN, NULL));

	memcpy(pkt, keyed, PKT_LEN);
	assert(!bfd_auth_md5_sign(pkt, PKT_LEN, METICULOUS_KEY "x"));
	assert(!bfd_auth_md5_sign(pkt, PKT_LEN, ""));
	assert(!bfd_auth_md5_sign(pkt, PKT_LEN, NULL));
	assert(!bfd_auth_md5_sign(pkt, PKT_LEN - 1, KEYED_KEY));
	assert(memcmp(pkt, keyed, PKT_LEN) == 0);
	printf("key length: ok\n");
}

static void test_window(void)
{
	/* A repeat is allowed for keyed MD5, not for the meticulous variant. */
	assert(bfd_auth_seq_in_window(1000, 1000, false, 3));
	assert(!bfd_auth_seq_in_window(1000, 1000, true, 3));
	assert(bfd_auth_seq_in_window(1000, 1001, true, 3));

	/* 3 * Detect Mult ahead is the last one allowed. */
	assert(bfd_auth_seq_in_window(1000, 1009, true, 3));
	assert(!bfd_auth_seq_in_window(1000, 1010, true, 3));
	assert(bfd_auth_seq_in_window(1000, 1000 + 765, false, 255));
	assert(!bfd_auth_seq_in_window(1000, 1000 + 766, false, 255));

	/* Behind is a replay, however close. */
	assert(!bfd_auth_seq_in_window(1000, 999, false, 3));

	/* Circular: past the wrap is ahead, not behind. */
	assert(bfd_auth_seq_in_window(0xfffffffe, 1, true, 3));
	assert(!bfd_auth_seq_in_window(1, 0xfffffffe, true, 3));
	printf("sequence window: ok\n");
}

/* Asked of the crypto library directly, not through the code under test. */
static bool md5_available(void)
{
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

	EVP_MD_CTX_free(ctx);
	return ok;
#else
	return true;
#endif
}

int main(int argc, char **argv)
{
	/* A FIPS provider refuses MD5, and then so must the helpers. */
	if (!md5_available()) {
		uint8_t pkt[PKT_LEN];

		memcpy(pkt, keyed, PKT_LEN);
		assert(!bfd_auth_md5_sign(pkt, PKT_LEN, KEYED_KEY));
		assert(!bfd_auth_md5_verify(keyed, PKT_LEN, KEYED_KEY));
		assert(!bfd_auth_md5_usable());
		printf("MD5 refused by the crypto provider: digests not tested\n");
		test_window();
		return 0;
	}

	assert(bfd_auth_md5_usable());
	test_digests();
	test_verify_failures();
	test_short_packet();
	test_key_length();
	test_window();
	return 0;
}
