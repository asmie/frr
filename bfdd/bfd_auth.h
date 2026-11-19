// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Piotr Olszewski */
#ifndef _BFDD_AUTH_H
#define _BFDD_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bfd_isaac.h"

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

/*
 * RFC 9986 optimized MD5 meticulous keyed ISAAC authentication, with the
 * procedures of RFC 9985.
 *
 * A packet is in one of two formats, told apart by the mode byte that
 * replaces the reserved one of keyed MD5. The MCI format is meticulous
 * keyed MD5 and signs the whole packet. The ISAAC format carries only a
 * number drawn from ISAAC for that sequence number: it shows who sent the
 * packet without protecting its contents, so it is only good for telling
 * the peer again what the last signed packet told it.
 *
 * Everything below works on packets and on this state alone, so that it
 * can be tested without a session.
 */
#define BFD_AUTH_OPT_MD5	 7 /* Auth Type */
#define BFD_AUTH_OPT_MODE_MCI	 1
#define BFD_AUTH_OPT_MODE_ISAAC	 2
#define BFD_AUTH_ISAAC_LEN	 16 /* type, length, key ID, mode, sequence, Seed, Auth Key */
#define BFD_AUTH_OPT_KEY_MIN_LEN 8  /* RFC 9986 Section 8 */
#define BFD_AUTH_OPT_PKT_MAX	 (24 + BFD_AUTH_MD5_LEN)

enum bfd_auth_opt_result {
	BFD_AUTH_OPT_OK = 0,
	/* Lengths or a mode neither format has. */
	BFD_AUTH_OPT_MALFORMED,
	/* ISAAC format where only a signed packet will do. */
	BFD_AUTH_OPT_NEEDS_MCI,
	/* No such key, or not the one this session is using. */
	BFD_AUTH_OPT_KEY_ID,
	/* Outside the window, or further ahead than the pages held. */
	BFD_AUTH_OPT_SEQUENCE,
	BFD_AUTH_OPT_DIGEST,
	BFD_AUTH_OPT_SEED,
	BFD_AUTH_OPT_AUTH_KEY,
};

/*
 * A key held for as long as the session stays up: RFC 9986 Section 8. Only
 * a signed packet that ends the session may arrive with another one.
 */
struct bfd_auth_opt_key {
	bool set;
	uint8_t id;
	char secret[BFD_AUTH_MD5_KEY_MAX_LEN + 1];
};

struct bfd_auth_opt {
	/* Up, and bfd_auth_opt_up() has been called for it. */
	bool up;

	/*
	 * Transmit. The generator is seeded with the first ISAAC format
	 * packet sent, whose sequence number then belongs to its first
	 * number; tx_base is the sequence number of the current page.
	 */
	struct bfd_auth_opt_key tx_key;
	struct bfd_isaac tx_isaac;
	uint32_t tx_base;
	uint32_t tx_seed;
	bool tx_seed_valid;
	bool tx_live;
	/* The header last signed, and how many more to sign before trusting it. */
	uint8_t tx_ref[24];
	bool tx_ref_valid;
	uint8_t tx_burst;
	/* MCI only until Up has been signalled for long enough. */
	bool up_sent;
	uint64_t hold_until;
	/* The peer has said Up in a signed packet. */
	bool peer_up;

	/* What bfd_auth_opt_tx_build() made, for bfd_auth_opt_tx_commit(). */
	struct {
		uint8_t hdr[24];
		uint32_t seq;
		uint8_t mode;
		bool up;
		bool poll_final;
		bool first_isaac;
	} tx_pending;

	/*
	 * Receive. rx_cur is the page rx_base starts and rx_isaac already
	 * holds the one after it, so that a packet for the next page can be
	 * checked without giving up the current one.
	 */
	struct bfd_auth_opt_key rx_key;
	struct bfd_isaac rx_isaac;
	uint32_t rx_cur[BFD_ISAAC_PAGE];
	uint32_t rx_base;
	uint32_t rx_seed;
	bool rx_live;
	/* The stream cannot be followed any more; only signed packets count. */
	bool rx_lost;
	/* Sequence number of the last packet accepted since Up. */
	uint32_t rx_last_seq;
	/* Header of the last signed Up packet, which ISAAC ones must repeat. */
	uint8_t rx_ref[24];
	bool rx_ref_valid;
};

/* What the session knows when a packet arrives. */
struct bfd_auth_opt_rx {
	/* bfd.SessionState is Up. */
	bool local_up;
	/* bfd.AuthSeqKnown and bfd.RcvAuthSeq. */
	bool seq_known;
	uint32_t last_seq;
	/* The configured key with the packet's key ID, if there is one. */
	const char *key;
};

/* What the session knows when it sends one. */
struct bfd_auth_opt_tx {
	/* bfd.XmitAuthSeq for this packet. */
	uint32_t seq;
	/* Monotonic time, in microseconds. */
	uint64_t now;
	/* The key to send with while the session is not up. */
	uint8_t key_id;
	const char *key;
};

/* Forget everything, the keys included. For any transition out of Up. */
void bfd_auth_opt_reset(struct bfd_auth_opt *opt);

/*
 * The session has gone up: start afresh with the key it will send with
 * until it goes down again. Without a Seed, which must come from a
 * CSPRNG, the ISAAC format is not used for as long as the session is up.
 *
 * What the peer sends is checked against a stream made from its Seed, the
 * key and our own discriminator. Only the last of those is ours to keep
 * fresh, so the session must come up with a discriminator it has not used
 * before, or a recording of an earlier time up can be played back at it.
 */
void bfd_auth_opt_up(struct bfd_auth_opt *opt, uint8_t key_id, const char *key,
		     const uint32_t *seed);

/*
 * Check a received packet whose Auth Type is BFD_AUTH_OPT_MD5; len is the
 * length its header declares. A refused packet changes nothing that
 * counts; at most it leaves its Seed in a generator not yet in use.
 */
enum bfd_auth_opt_result bfd_auth_opt_rx_verify(struct bfd_auth_opt *opt, const uint8_t *pkt,
						size_t len, const struct bfd_auth_opt_rx *in);

/*
 * Take note of an accepted packet once the state machine has seen it.
 * in is what the packet was verified with, but for local_up, which says
 * what state that left the session in.
 */
void bfd_auth_opt_rx_commit(struct bfd_auth_opt *opt, const uint8_t *pkt,
			    const struct bfd_auth_opt_rx *in);

/*
 * Add the authentication section to a packet whose 24 byte header is
 * filled in, in a buffer of BFD_AUTH_OPT_PKT_MAX bytes. Returns the
 * packet's length, or 0 if there is no key to send it with.
 */
size_t bfd_auth_opt_tx_build(struct bfd_auth_opt *opt, uint8_t *pkt,
			     const struct bfd_auth_opt_tx *in);

/*
 * The packet just built has been sent. A packet that was not sent is
 * simply not committed: its sequence number is still free.
 *
 * hold is how long Up must be signalled in the MCI format before the
 * ISAAC one may be used, counted from the first Up packet sent.
 */
void bfd_auth_opt_tx_commit(struct bfd_auth_opt *opt, uint64_t now, uint64_t hold);

#endif /* _BFDD_AUTH_H */
