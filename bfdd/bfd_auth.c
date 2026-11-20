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

bool bfd_auth_md5_usable(void)
{
	uint8_t pkt[BFD_AUTH_HDR_LEN + BFD_AUTH_MD5_LEN] = {};
	static int usable = -1;

	/* What the provider allows does not change while we run. */
	if (usable < 0)
		usable = bfd_auth_md5_sign(pkt, sizeof(pkt), "probe");

	return usable;
}

/*
 * RFC 9986 optimized MD5 meticulous keyed ISAAC authentication.
 */

/* Where things are in the control packet header and the section after it. */
#define HDR_FLAGS	1
#define HDR_DETECT_MULT 2
#define HDR_LEN		3
#define HDR_YOUR_DISCR	8
#define SEC_TYPE	(BFD_AUTH_HDR_LEN + 0)
#define SEC_LEN		(BFD_AUTH_HDR_LEN + 1)
#define SEC_KEY_ID	(BFD_AUTH_HDR_LEN + 2)
#define SEC_MODE	(BFD_AUTH_HDR_LEN + 3)
#define SEC_SEQ		(BFD_AUTH_HDR_LEN + 4)
#define SEC_SEED	(BFD_AUTH_HDR_LEN + 8)
#define SEC_AUTH_KEY	(BFD_AUTH_HDR_LEN + 12)

#define FLAG_POLL  0x20
#define FLAG_FINAL 0x10
#define FLAG_AUTH  0x04
#define STATE_INIT 2
#define STATE_UP   3

#define MCI_PKT_LEN   (BFD_AUTH_HDR_LEN + BFD_AUTH_MD5_LEN)
#define ISAAC_PKT_LEN (BFD_AUTH_HDR_LEN + BFD_AUTH_ISAAC_LEN)

/*
 * How far a signed packet may move the sequence number on and still be
 * followed by the generator: the widest window RFC 5880 allows.
 */
#define OPT_MAX_STEP (3U * UINT8_MAX)

static inline uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static inline bool opt_state_up(const uint8_t *pkt)
{
	return pkt[HDR_FLAGS] >> 6 == STATE_UP;
}

/* Down or AdminDown: what ends a session that is up. */
static inline bool opt_state_down(const uint8_t *pkt)
{
	return pkt[HDR_FLAGS] >> 6 < STATE_INIT;
}

static bool opt_key_usable(const char *key)
{
	size_t len = key ? strnlen(key, BFD_AUTH_MD5_KEY_MAX_LEN + 1) : 0;

	return len >= BFD_AUTH_OPT_KEY_MIN_LEN && len <= BFD_AUTH_MD5_KEY_MAX_LEN;
}

static void opt_key_set(struct bfd_auth_opt_key *k, uint8_t id, const char *key)
{
	k->set = opt_key_usable(key);
	if (!k->set)
		return;

	k->id = id;
	strlcpy(k->secret, key, sizeof(k->secret));
}

/*
 * What an ISAAC format packet has to repeat: the header as last signed.
 * Poll and Final are left out, since a signed Poll or Final is followed
 * by packets that have neither, and so is the length, which differs
 * between the two formats.
 */
static void opt_header_ref(uint8_t ref[BFD_AUTH_HDR_LEN], const uint8_t *pkt)
{
	memcpy(ref, pkt, BFD_AUTH_HDR_LEN);
	ref[HDR_FLAGS] &= ~(FLAG_POLL | FLAG_FINAL);
	ref[HDR_LEN] = 0;
}

void bfd_auth_opt_reset(struct bfd_auth_opt *opt)
{
	explicit_bzero(opt, sizeof(*opt));
}

void bfd_auth_opt_up(struct bfd_auth_opt *opt, uint8_t key_id, const char *key,
		     const uint32_t *seed)
{
	bfd_auth_opt_reset(opt);

	opt->up = true;
	opt_key_set(&opt->tx_key, key_id, key);
	if (seed) {
		opt->tx_seed = *seed;
		opt->tx_seed_valid = true;
	}
}

/* Move on to the page after the current one. */
static void opt_rx_flip(struct bfd_auth_opt *opt)
{
	memcpy(opt->rx_cur, opt->rx_isaac.rsl, sizeof(opt->rx_cur));
	bfd_isaac_next_page(&opt->rx_isaac);
	opt->rx_base += BFD_ISAAC_PAGE;
}

/*
 * A packet with this sequence number was accepted. Keep the number that
 * comes after it on the current page, so that there is always a full
 * page ahead of whatever arrives next.
 */
static void opt_rx_advance(struct bfd_auth_opt *opt, uint32_t seq)
{
	opt->rx_last_seq = seq;
	while (seq + 1 - opt->rx_base >= BFD_ISAAC_PAGE)
		opt_rx_flip(opt);
}

static enum bfd_auth_opt_result opt_rx_isaac(struct bfd_auth_opt *opt, const uint8_t *pkt,
					     const struct bfd_auth_opt_rx *in, const char *key)
{
	uint8_t hdr[BFD_AUTH_HDR_LEN];
	uint32_t seq = get32(pkt + SEC_SEQ);
	uint32_t seed = get32(pkt + SEC_SEED);
	uint32_t auth_key = get32(pkt + SEC_AUTH_KEY);
	uint32_t step, span, idx;

	/*
	 * Nothing here is signed, so it can only stand for a signed Up
	 * packet this session has already accepted, with no Poll or Final,
	 * and has to say what that one said. The reference is always an Up
	 * packet, so comparing against it covers the state as well. The
	 * local state is asked for separately, in case the session went
	 * down without this being reset.
	 */
	if (!in->local_up || !opt->rx_ref_valid || opt->rx_lost ||
	    (pkt[HDR_FLAGS] & (FLAG_POLL | FLAG_FINAL)))
		return BFD_AUTH_OPT_NEEDS_MCI;

	opt_header_ref(hdr, pkt);
	if (memcmp(hdr, opt->rx_ref, sizeof(hdr)) != 0)
		return BFD_AUTH_OPT_NEEDS_MCI;

	/* Detect Mult can be trusted by now: it is the signed one. */
	step = seq - opt->rx_last_seq;
	if (step == 0 || step > 3U * pkt[HDR_DETECT_MULT])
		return BFD_AUTH_OPT_SEQUENCE;

	if (!opt->rx_live) {
		/*
		 * RFC 9986 Section 10.2 has the stream start at the sequence
		 * number expected next, so that a packet arriving later sits
		 * that much further in. That takes every packet lost since
		 * for one of the stream, and no packet before for one, and
		 * neither need be so: signed packets may have been lost just
		 * before the stream started, and it may have started unseen
		 * before signed packets that did arrive. What is certain is
		 * that it started after the first packet of this time up.
		 *
		 * So the number is looked for wherever on the first page that
		 * leaves room for. Found among the packets lost since the
		 * last one accepted, it says where the stream began. Found
		 * further back it is only kept in mind: that is a lot of
		 * places for a made up number to turn up in, so the packet
		 * is let go and the next has to bear it out.
		 *
		 * The generator is seeded in place; it only counts once a number
		 * checks out, which a made up Seed will not manage.
		 */
		bfd_isaac_seed(&opt->rx_isaac, seed, get32(pkt + HDR_YOUR_DISCR),
			       (const uint8_t *)key, strlen(key));

		idx = seq - opt->rx_cand_base;
		if (!opt->rx_cand || seed != opt->rx_cand_seed || idx >= BFD_ISAAC_PAGE ||
		    opt->rx_isaac.rsl[idx] != auth_key) {
			/* A span of 0 is one of 2^32, and as good as any other. */
			span = seq - opt->rx_first_seq;
			for (idx = MIN(span - 1, BFD_ISAAC_PAGE - 1);
			     opt->rx_isaac.rsl[idx] != auth_key; idx--)
				if (idx == 0)
					return BFD_AUTH_OPT_AUTH_KEY;

			if (idx >= step) {
				opt->rx_cand = true;
				opt->rx_cand_seed = seed;
				opt->rx_cand_base = seq - idx;
				return BFD_AUTH_OPT_AUTH_KEY;
			}
		}

		opt->rx_base = seq - idx - BFD_ISAAC_PAGE;
		opt_rx_flip(opt);
		opt->rx_seed = seed;
		opt->rx_live = true;
	} else {
		if (seed != opt->rx_seed)
			return BFD_AUTH_OPT_SEED;

		idx = seq - opt->rx_base;
		if (idx >= 2 * BFD_ISAAC_PAGE)
			return BFD_AUTH_OPT_SEQUENCE;
		if (auth_key != (idx < BFD_ISAAC_PAGE ? opt->rx_cur[idx]
						      : opt->rx_isaac.rsl[idx - BFD_ISAAC_PAGE]))
			return BFD_AUTH_OPT_AUTH_KEY;
	}

	opt_rx_advance(opt, seq);
	return BFD_AUTH_OPT_OK;
}

enum bfd_auth_opt_result bfd_auth_opt_rx_verify(struct bfd_auth_opt *opt, const uint8_t *pkt,
						size_t len, const struct bfd_auth_opt_rx *in)
{
	const char *key = in->key, *alt = NULL;
	uint8_t mode;
	bool down;

	if (len < ISAAC_PKT_LEN || pkt[HDR_LEN] != len || pkt[SEC_TYPE] != BFD_AUTH_OPT_MD5)
		return BFD_AUTH_OPT_MALFORMED;

	mode = pkt[SEC_MODE];
	if (mode == BFD_AUTH_OPT_MODE_MCI) {
		if (len != MCI_PKT_LEN || pkt[SEC_LEN] != BFD_AUTH_MD5_LEN)
			return BFD_AUTH_OPT_MALFORMED;
	} else if (mode == BFD_AUTH_OPT_MODE_ISAAC) {
		if (len != ISAAC_PKT_LEN || pkt[SEC_LEN] != BFD_AUTH_ISAAC_LEN)
			return BFD_AUTH_OPT_MALFORMED;
	} else {
		return BFD_AUTH_OPT_MALFORMED;
	}

	/*
	 * Once up, the peer stays with the key it came up with. A signed
	 * packet saying it is down ends the session, and may also come with
	 * whatever key is configured now: after a change of keys, be it of
	 * the ID or only of the secret, that is the only way the peer has of
	 * telling us so. Init does not end it and gets no such leave.
	 */
	down = mode == BFD_AUTH_OPT_MODE_MCI && opt_state_down(pkt);
	if (opt->rx_key.set) {
		if (pkt[SEC_KEY_ID] == opt->rx_key.id) {
			key = opt->rx_key.secret;
			alt = down ? in->key : NULL;
		} else if (!down) {
			return BFD_AUTH_OPT_KEY_ID;
		}
	}
	if (!opt_key_usable(key))
		return BFD_AUTH_OPT_KEY_ID;

	if (mode == BFD_AUTH_OPT_MODE_ISAAC)
		return opt_rx_isaac(opt, pkt, in, key);

	if (in->seq_known && !bfd_auth_seq_in_window(in->last_seq, get32(pkt + SEC_SEQ), true,
						     pkt[HDR_DETECT_MULT]))
		return BFD_AUTH_OPT_SEQUENCE;

	if (bfd_auth_md5_verify(pkt, len, key) ||
	    (opt_key_usable(alt) && bfd_auth_md5_verify(pkt, len, alt)))
		return BFD_AUTH_OPT_OK;

	return BFD_AUTH_OPT_DIGEST;
}

void bfd_auth_opt_rx_commit(struct bfd_auth_opt *opt, const uint8_t *pkt,
			    const struct bfd_auth_opt_rx *in)
{
	uint32_t seq, step;

	/* An ISAAC format packet was dealt with when it was verified. */
	if (!opt->up || !in->local_up || pkt[SEC_MODE] != BFD_AUTH_OPT_MODE_MCI)
		return;

	/*
	 * The sequence number goes on while packets are signed, and the
	 * generator has to keep up with it: RFC 9986 Section 12. A step no
	 * window allows means the sequence number was picked up again from
	 * nothing, and there is no telling where in the stream it is.
	 */
	seq = get32(pkt + SEC_SEQ);
	if (!opt->rx_first_known) {
		opt->rx_first_seq = seq;
		opt->rx_first_known = true;
	}
	if (opt->rx_live) {
		step = seq - opt->rx_last_seq;
		if (step == 0 || step > OPT_MAX_STEP) {
			opt->rx_live = false;
			opt->rx_lost = true;
		} else {
			opt_rx_advance(opt, seq);
		}
	}
	opt->rx_last_seq = seq;

	if (!opt_state_up(pkt)) {
		opt->rx_ref_valid = false;
		opt->peer_up = false;
		return;
	}

	opt_header_ref(opt->rx_ref, pkt);
	opt->rx_ref_valid = true;
	opt->peer_up = true;
	if (!opt->rx_key.set)
		opt_key_set(&opt->rx_key, pkt[SEC_KEY_ID], in->key);
}

/* Whether the packet being built may go out in the ISAAC format. */
static bool opt_tx_isaac_allowed(const struct bfd_auth_opt *opt, uint64_t now)
{
	return opt->peer_up && opt->tx_seed_valid && opt->up_sent && now >= opt->hold_until &&
	       !opt->tx_pending.poll_final && opt->tx_burst == 0 && opt->tx_ref_valid &&
	       memcmp(opt->tx_pending.hdr, opt->tx_ref, sizeof(opt->tx_ref)) == 0;
}

size_t bfd_auth_opt_tx_build(struct bfd_auth_opt *opt, uint8_t *pkt,
			     const struct bfd_auth_opt_tx *in)
{
	const char *key = in->key;
	uint8_t key_id = in->key_id;
	uint8_t mode = BFD_AUTH_OPT_MODE_MCI;
	bool up = opt->up && opt_state_up(pkt);
	bool first_isaac = false;

	/* Up, the key is the one the session came up with. */
	if (up) {
		if (!opt->tx_key.set)
			return 0;
		key = opt->tx_key.secret;
		key_id = opt->tx_key.id;
	} else if (!opt_key_usable(key)) {
		return 0;
	}

	pkt[HDR_FLAGS] |= FLAG_AUTH;
	opt_header_ref(opt->tx_pending.hdr, pkt);
	opt->tx_pending.seq = in->seq;
	opt->tx_pending.up = up;
	opt->tx_pending.poll_final = pkt[HDR_FLAGS] & (FLAG_POLL | FLAG_FINAL);

	if (up && opt_tx_isaac_allowed(opt, in->now)) {
		/*
		 * Seeded with the first packet to use it, so that Your
		 * Discriminator is the one the peer will read off that
		 * packet. Only counts once the packet has gone out.
		 */
		if (opt->tx_live) {
			if (in->seq - opt->tx_base < BFD_ISAAC_PAGE)
				mode = BFD_AUTH_OPT_MODE_ISAAC;
		} else if (bfd_isaac_seed(&opt->tx_isaac, opt->tx_seed, get32(pkt + HDR_YOUR_DISCR),
					  (const uint8_t *)key, strlen(key))) {
			opt->tx_base = in->seq;
			first_isaac = true;
			mode = BFD_AUTH_OPT_MODE_ISAAC;
		}
	}
	opt->tx_pending.mode = mode;
	opt->tx_pending.first_isaac = first_isaac;

	pkt[SEC_TYPE] = BFD_AUTH_OPT_MD5;
	pkt[SEC_KEY_ID] = key_id;
	pkt[SEC_MODE] = mode;
	put32(pkt + SEC_SEQ, in->seq);

	if (mode == BFD_AUTH_OPT_MODE_ISAAC) {
		pkt[HDR_LEN] = ISAAC_PKT_LEN;
		pkt[SEC_LEN] = BFD_AUTH_ISAAC_LEN;
		put32(pkt + SEC_SEED, opt->tx_seed);
		put32(pkt + SEC_AUTH_KEY, opt->tx_isaac.rsl[in->seq - opt->tx_base]);
		return ISAAC_PKT_LEN;
	}

	pkt[HDR_LEN] = MCI_PKT_LEN;
	pkt[SEC_LEN] = BFD_AUTH_MD5_LEN;
	return bfd_auth_md5_sign(pkt, MCI_PKT_LEN, key) ? MCI_PKT_LEN : 0;
}

void bfd_auth_opt_tx_commit(struct bfd_auth_opt *opt, uint64_t now, uint64_t hold)
{
	uint8_t burst = opt->tx_pending.hdr[HDR_DETECT_MULT];
	uint8_t left = opt->tx_burst ? opt->tx_burst - 1 : 0;
	uint8_t want = 0;

	/* The generator follows the sequence number whatever was sent. */
	if (opt->tx_live && opt->tx_pending.seq + 1 - opt->tx_base >= BFD_ISAAC_PAGE) {
		bfd_isaac_next_page(&opt->tx_isaac);
		opt->tx_base += BFD_ISAAC_PAGE;
	}

	if (!opt->tx_pending.up)
		return;

	if (!opt->up_sent) {
		opt->up_sent = true;
		opt->hold_until = now + hold;
	}

	if (opt->tx_pending.mode == BFD_AUTH_OPT_MODE_ISAAC) {
		if (opt->tx_pending.first_isaac)
			opt->tx_live = true;
		return;
	}

	/*
	 * A change is signed Detect Mult times over, as is the return to no
	 * Poll or Final, so that losing one packet does not leave the peer
	 * holding a header we have moved on from. How many it can lose is
	 * down to the Detect Mult it last heard, so when that is lowered the
	 * old one still counts, and a run already under way is never cut
	 * short.
	 */
	if (opt->tx_ref_valid)
		burst = MAX(burst, opt->tx_ref[HDR_DETECT_MULT]);

	if (opt->tx_pending.poll_final)
		want = burst;
	else if (!opt->tx_ref_valid ||
		 memcmp(opt->tx_pending.hdr, opt->tx_ref, sizeof(opt->tx_ref)) != 0)
		want = burst - 1;
	opt->tx_burst = MAX(want, left);

	memcpy(opt->tx_ref, opt->tx_pending.hdr, sizeof(opt->tx_ref));
	opt->tx_ref_valid = true;
}
