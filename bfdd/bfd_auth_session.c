// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 9986 optimized authentication as a session sees it: which sessions
 * may use it and with which keys, and what has to happen to the state in
 * bfd_auth.c as a session comes up, goes down and has its keys changed.
 *
 * Copyright (c) 2026 Piotr Olszewski
 */

#include <zebra.h>

#include "lib/network.h"

#include "bfd.h"
#include "bfd_auth.h"

DEFINE_MTYPE_STATIC(BFDD, BFDD_AUTH_OPT, "optimized authentication state");

/* Where the key ID and the mode byte are in the authentication section. */
#define SEC_KEY_ID 2
#define SEC_MODE   3

/* Monotonic time in microseconds, as the timers of a session are kept. */
static inline uint64_t bfd_auth_opt_now(void)
{
	return monotime_ns() / 1000;
}

/* An MD5 key of a length the type takes, with an ID that fits the packet. */
static bool bfd_auth_opt_key_fits(const struct key *key)
{
	size_t len;

	if (key->hash_algo != KEYCHAIN_ALGO_MD5 || key->string == NULL || key->index > UINT8_MAX)
		return false;

	len = strlen(key->string);
	return len >= BFD_AUTH_OPT_KEY_MIN_LEN && len <= BFD_AUTH_MD5_KEY_MAX_LEN;
}

/* A lifetime as lib/keychain reads it: no start is no lifetime at all. */
static bool bfd_auth_opt_in_lifetime(const struct key_range *range, time_t now)
{
	return range->start == 0 ||
	       (range->start <= now && (range->end >= now || range->end == -1));
}

struct key *bfd_auth_opt_key_find_send(const struct keychain *kc)
{
	struct listnode *node;
	struct key *key;
	time_t now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(kc->key, node, key))
		if (bfd_auth_opt_key_fits(key) && bfd_auth_opt_in_lifetime(&key->send, now))
			return key;

	return NULL;
}

/* The key a received packet names, if it may be accepted with it now. */
static const char *bfd_auth_opt_accept_key(const struct bfd_session *bs, uint8_t id)
{
	const struct key *key = bs->kc ? key_lookup(bs->kc, id) : NULL;

	if (key == NULL || !bfd_auth_opt_key_fits(key) ||
	    !bfd_auth_opt_in_lifetime(&key->accept, time(NULL)))
		return NULL;

	return key->string;
}

struct key *bfd_session_auth_send_key(const struct bfd_session *bs)
{
	if (bs->kc == NULL)
		return NULL;
	if (bs->auth_optimized)
		return bfd_auth_opt_key_find_send(bs->kc);
	return bfd_keychain_key_find_active(bs->kc, bs->auth_meticulous);
}

enum bfd_auth_opt_hold bfd_auth_opt_hold_reason(const struct bfd_session *bs)
{
	if (!bs->auth_optimized)
		return BFD_AUTH_OPT_HOLD_NONE;
	if (bs->bfd_mode != BFD_MODE_TYPE_BFD)
		return BFD_AUTH_OPT_HOLD_SBFD;
	if (bglobal.bg_use_dplane)
		return BFD_AUTH_OPT_HOLD_DPLANE;
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_DEMAND))
		return BFD_AUTH_OPT_HOLD_DEMAND;
	if (bs->detect_mult > BFD_AUTH_OPT_DETECT_MULT_MAX)
		return BFD_AUTH_OPT_HOLD_DETECT_MULT;
	return BFD_AUTH_OPT_HOLD_NONE;
}

const char *bfd_auth_opt_hold_str(enum bfd_auth_opt_hold hold)
{
	switch (hold) {
	case BFD_AUTH_OPT_HOLD_NONE:
		break;
	case BFD_AUTH_OPT_HOLD_SBFD:
		return "it is not available for S-BFD";
	case BFD_AUTH_OPT_HOLD_DPLANE:
		return "it is not available with a distributed data plane";
	case BFD_AUTH_OPT_HOLD_DEMAND:
		return "it is not available with demand mode";
	case BFD_AUTH_OPT_HOLD_DETECT_MULT:
		return "the detect multiplier is above " STRINGIFY(BFD_AUTH_OPT_DETECT_MULT_MAX);
	}
	return "none";
}

const char *bfd_auth_opt_session_unused(const struct bfd_session *bs)
{
	const char *name = bfd_session_auth_key_chain_name(bs);
	const struct keychain *kc;

	if (bs->auth_opt_hold != BFD_AUTH_OPT_HOLD_NONE)
		return bfd_auth_opt_hold_str(bs->auth_opt_hold);
	if (name == NULL)
		return "no key-chain is configured";

	/* Looked up here: one with no key in it yet is not told to us. */
	kc = keychain_lookup(name);
	if (kc == NULL)
		return "the key-chain does not exist";
	if (bfd_auth_opt_key_find_send(kc) == NULL)
		return "the key-chain has no md5 key to send with (8 to 16 bytes, ID up to 255, in its send lifetime)";
	if (!bs->discr_strong)
		return "the system has no random numbers to give";
	if (!bfd_auth_md5_usable())
		return "the crypto library refuses MD5";
	return NULL;
}

const char *bfd_auth_opt_result_str(enum bfd_auth_opt_result res)
{
	switch (res) {
	case BFD_AUTH_OPT_OK:
		break;
	case BFD_AUTH_OPT_MALFORMED:
		return "malformed authentication section";
	case BFD_AUTH_OPT_NEEDS_MCI:
		return "ISAAC format where a signed packet is needed";
	case BFD_AUTH_OPT_KEY_ID:
		return "no such key, or not the one the session uses";
	case BFD_AUTH_OPT_SEQUENCE:
		return "sequence number out of range";
	case BFD_AUTH_OPT_DIGEST:
		return "digest mismatch";
	case BFD_AUTH_OPT_SEED:
		return "Seed changed";
	case BFD_AUTH_OPT_AUTH_KEY:
		return "Auth Key mismatch";
	}
	return "ok";
}

/*
 * Whether a key the session came up with is still what the chain holds
 * under that ID, and in its lifetime. from and until are drawn in to that
 * lifetime where it has a start and an end.
 */
static bool bfd_auth_opt_pin_holds(const struct bfd_session *bs, const struct bfd_auth_opt_key *pin,
				   bool send, time_t now, time_t *from, time_t *until)
{
	const struct key *key = bs->kc ? key_lookup(bs->kc, pin->id) : NULL;
	const struct key_range *range;

	if (key == NULL || !bfd_auth_opt_key_fits(key) || strcmp(key->string, pin->secret) != 0)
		return false;

	range = send ? &key->send : &key->accept;
	if (!bfd_auth_opt_in_lifetime(range, now))
		return false;

	if (range->start > *from)
		*from = range->start;
	if (range->start != 0 && range->end != -1 && (*until == 0 || range->end < *until))
		*until = range->end;
	return true;
}

/*
 * Whether the session still has both keys it came up with, and from when
 * until when that is so by their lifetimes: 0 for no bound.
 */
static bool bfd_auth_opt_keys_hold(const struct bfd_session *bs, time_t now, time_t *from,
				   time_t *until)
{
	const struct bfd_auth_opt *opt = bs->auth_opt;

	*from = *until = 0;
	return opt->tx_key.set &&
	       bfd_auth_opt_pin_holds(bs, &opt->tx_key, true, now, from, until) &&
	       (!opt->rx_key.set ||
		bfd_auth_opt_pin_holds(bs, &opt->rx_key, false, now, from, until));
}

/*
 * RFC 9986 Section 11.2 has a session keep its keys for as long as it is
 * up. So when one of them is changed, removed or runs out, the session
 * goes down, and comes back up with what the chain holds then. It does
 * not sign a last packet with the key it has just lost.
 */
static void bfd_auth_opt_keys_check(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);
	time_t now = time(NULL);

	if (!bs->auth_opt->up || bs->ses_state != PTM_BFD_UP)
		return;

	if (!bfd_auth_opt_keys_hold(bs, now, &bs->auth_opt_keys_from, &bs->auth_opt_keys_until)) {
		/* RFC 5880 has no diagnostic for this, so it goes in the log. */
		zlog_info("BFD: session [%s] lost a key it came up with, taking it down",
			  bs_to_string(bs));
		bs->stats.auth_opt_keys_lost++;
		ptm_bfd_sess_dn(bs, BD_OK, false);
		return;
	}

	bs->auth_opt_keys_gone = false;

	/*
	 * Look again once the first of the lifetimes is over, and once a day
	 * until then. The timer does not follow the wall clock the lifetimes
	 * are in, which is why the bounds are kept as well:
	 * bfd_auth_opt_keys_lost() goes by them.
	 */
	if (bs->auth_opt_keys_until != 0)
		event_add_timer(master, bfd_auth_opt_keys_check, bs,
				MIN(bs->auth_opt_keys_until - now + 1, ONE_DAY_SECOND),
				&bs->auth_opt_keys_ev);
}

/* Not done on the spot: the callers are in the middle of other things. */
static void bfd_auth_opt_keys_recheck(struct bfd_session *bs)
{
	event_cancel(&bs->auth_opt_keys_ev);
	event_add_event(master, bfd_auth_opt_keys_check, bs, 0, &bs->auth_opt_keys_ev);
}

/*
 * Whether a session that is up may no longer use its keys: one of them
 * was seen to be gone, or the clock has left the lifetimes. The session
 * is on its way down then, and nothing is sent or taken until it is.
 */
static bool bfd_auth_opt_keys_lost(struct bfd_session *bs)
{
	time_t now;

	if (bs->auth_opt_keys_gone)
		return true;

	now = time(NULL);
	if (now >= bs->auth_opt_keys_from &&
	    (bs->auth_opt_keys_until == 0 || now <= bs->auth_opt_keys_until))
		return false;

	bs->auth_opt_keys_gone = true;
	bfd_auth_opt_keys_recheck(bs);
	return true;
}

/*
 * RFC 9985 Section 5: a session whose packets are mostly not signed has
 * the peer show now and then that it still has the key, by answering a
 * signed Poll with a signed Final. One that does not within twice the
 * time it would take to notice us gone is not the peer any more.
 */
enum {
	REAUTH_IDLE = 0, /* waiting out the interval */
	REAUTH_DUE,	 /* a Poll is to go out */
	REAUTH_SENT,	 /* and has, with no Final back yet */
};

uint32_t bfd_auth_opt_reauth_interval(const struct bfd_session *bs)
{
	if (bs->peer_profile.auth_config.has_reauth_interval)
		return bs->peer_profile.auth_config.reauth_interval;
	if (bs->profile && bs->profile->auth_config.has_reauth_interval)
		return bs->profile->auth_config.reauth_interval;
	return BFD_AUTH_OPT_REAUTH_DEFAULT;
}

static void bfd_auth_opt_reauth_timer(struct event *t);

static void bfd_auth_opt_reauth_stop(struct bfd_session *bs)
{
	event_cancel(&bs->auth_opt_reauth_ev);
	bs->auth_opt_reauth_phase = REAUTH_IDLE;
}

/*
 * Start on the next interval, cut short by up to a quarter so that the
 * sessions of a system do not all come due together. The interval is a
 * day at most, so in milliseconds it fits a long wherever that is 32 bits.
 */
static void bfd_auth_opt_reauth_idle(struct bfd_session *bs)
{
	bfd_auth_opt_reauth_stop(bs);
	if (bs->auth_opt_reauth != 0)
		event_add_timer_msec(master, bfd_auth_opt_reauth_timer, bs,
				     (long)bs->auth_opt_reauth * (750 + frr_weak_random() % 251),
				     &bs->auth_opt_reauth_ev);
}

/*
 * Give it twice the peer's detection time for our packets, as that is
 * now: for the Poll to go out, and then again for the Final to come.
 */
static void bfd_auth_opt_reauth_wait(struct bfd_session *bs, uint8_t phase)
{
	uint64_t usec = 2 * (uint64_t)bs->detect_mult * bs->xmt_TO;

	event_cancel(&bs->auth_opt_reauth_ev);
	bs->auth_opt_reauth_phase = phase;
	event_add_timer_msec(master, bfd_auth_opt_reauth_timer, bs, usec / 1000,
			     &bs->auth_opt_reauth_ev);
}

static void bfd_auth_opt_reauth_timer(struct event *t)
{
	struct bfd_session *bs = EVENT_ARG(t);

	if (bs->ses_state != PTM_BFD_UP)
		return;

	/* A Poll Sequence already under way will do as well as a new one. */
	if (bs->auth_opt_reauth_phase == REAUTH_IDLE) {
		if (!bs->polling)
			bfd_set_polling(bs);
		bfd_auth_opt_reauth_wait(bs, REAUTH_DUE);
		return;
	}

	zlog_info("BFD: session [%s] was not authenticated again, %s; taking it down",
		  bs_to_string(bs),
		  bs->auth_opt_reauth_phase == REAUTH_DUE ? "no Poll could be sent"
							  : "no signed Final came back");
	bs->stats.auth_opt_reauth_failed++;
	ptm_bfd_sess_dn(bs, BD_CONTROL_EXPIRED, false);
}

void bfd_auth_opt_session_apply(struct bfd_session *bs, bool was_optimized)
{
	bool want = bs->auth_optimized && bs->auth_opt_hold == BFD_AUTH_OPT_HOLD_NONE;

	uint32_t reauth = bfd_auth_opt_reauth_interval(bs);
	time_t from, until;

	if (want == (bs->auth_opt != NULL) && was_optimized == bs->auth_optimized) {
		if (!want || !bs->auth_opt->up)
			return;

		/* A check that is under way is seen through, unless turned off. */
		if (reauth != bs->auth_opt_reauth) {
			bs->auth_opt_reauth = reauth;
			if (reauth == 0 || bs->auth_opt_reauth_phase == REAUTH_IDLE)
				bfd_auth_opt_reauth_idle(bs);
		}

		/*
		 * The chain may be what has changed. Taking the session down
		 * waits its turn, but a key that is gone is not used by
		 * whatever is to run before that.
		 */
		if (!bfd_auth_opt_keys_hold(bs, time(NULL), &from, &until))
			bs->auth_opt_keys_gone = true;
		bfd_auth_opt_keys_recheck(bs);
		return;
	}

	/*
	 * What the session authenticates with has changed under it. The
	 * state is there before the session is taken down, so that it can
	 * say so with what it is to use from now on.
	 */
	if (want && bs->auth_opt == NULL)
		bs->auth_opt = XCALLOC(MTYPE_BFDD_AUTH_OPT, sizeof(*bs->auth_opt));

	/*
	 * An S-BFD session is not touched: it has its own way down, which it
	 * takes when what the reflector sends is no longer accepted, and
	 * ptm_bfd_sess_dn() would cost it the discriminator it was given.
	 */
	if (bs->bfd_mode == BFD_MODE_TYPE_BFD &&
	    (bs->ses_state == PTM_BFD_INIT || bs->ses_state == PTM_BFD_UP))
		ptm_bfd_sess_dn(bs, BD_OK, false);

	if (!want)
		bfd_auth_opt_session_free(bs);
}

/* The session is not up any more, or only now: nothing is known of its keys. */
static void bfd_auth_opt_keys_forget(struct bfd_session *bs)
{
	event_cancel(&bs->auth_opt_keys_ev);
	bs->auth_opt_keys_from = bs->auth_opt_keys_until = 0;
	bs->auth_opt_keys_gone = false;
}

void bfd_auth_opt_session_free(struct bfd_session *bs)
{
	bfd_auth_opt_keys_forget(bs);
	bfd_auth_opt_reauth_stop(bs);
	if (bs->auth_opt == NULL)
		return;

	bfd_auth_opt_reset(bs->auth_opt);
	XFREE(MTYPE_BFDD_AUTH_OPT, bs->auth_opt);
}

void bfd_auth_opt_session_up(struct bfd_session *bs)
{
	const struct key *key;
	uint32_t seed;
	bool seeded;

	if (bs->auth_opt == NULL)
		return;

	/*
	 * RFC 9986 Section 10 wants the Seed from a CSPRNG. Without one the
	 * session is no worse off for signing every packet this time up.
	 */
	seeded = frr_csprng_bytes(&seed, sizeof(seed));
	if (!seeded)
		zlog_warn("BFD: session [%s] has no random Seed to be had, every packet will be signed",
			  bs_to_string(bs));

	key = bs->kc ? bfd_auth_opt_key_find_send(bs->kc) : NULL;
	bfd_auth_opt_keys_forget(bs);
	bfd_auth_opt_up(bs->auth_opt, key ? key->index : 0, key ? key->string : NULL,
			seeded ? &seed : NULL);
	bfd_auth_opt_keys_recheck(bs);

	bs->auth_opt_reauth = bfd_auth_opt_reauth_interval(bs);
	bfd_auth_opt_reauth_idle(bs);
}

void bfd_auth_opt_session_down(struct bfd_session *bs, int old_state)
{
	if (bs->auth_opt == NULL)
		return;

	bfd_auth_opt_keys_forget(bs);
	bfd_auth_opt_reauth_stop(bs);
	bfd_auth_opt_reset(bs->auth_opt);
	bs->auth_opt_tx_mode = bs->auth_opt_rx_mode = 0;

	/*
	 * What the peer sends is tied to our discriminator, and a signed
	 * packet is only refused as old for as long as its sequence number
	 * is remembered. A discriminator the peer has been told is used for
	 * that one time up, or what it sent could be played back later.
	 */
	if ((old_state == PTM_BFD_INIT || old_state == PTM_BFD_UP) && !bglobal.bg_shutdown)
		bfd_session_renew_discr(bs);
}

/*
 * A discriminator random() gave may be one the session has had before,
 * which is no better than not changing it: bfd_auth_opt_session_down().
 * So with one of those the session neither sends nor takes anything, and
 * tries for a better one for as long as it is down. The packet in hand is
 * not for it even then: it was made out to the old one.
 */
static bool bfd_auth_opt_discr_ok(struct bfd_session *bs)
{
	static bool warned;

	if (bs->discr_strong)
		return true;

	if (bs->ses_state == PTM_BFD_DOWN)
		bfd_session_renew_discr(bs);

	if (!bs->discr_strong && !warned) {
		warned = true;
		zlog_warn(
			"BFD: the system has no random numbers to give; sessions with optimized authentication stay down until it has");
	}
	return false;
}

size_t bfd_auth_opt_session_build(struct bfd_session *bs, uint8_t *pkt)
{
	struct bfd_auth_opt_tx in = {
		.seq = bs->auth_seq_num + 1,
		.now = bfd_auth_opt_now(),
	};
	const struct key *key;

	if (bs->auth_opt == NULL)
		return 0;

	/* Up, it is the key the session came up with and none is looked for. */
	if (bs->ses_state != PTM_BFD_UP || !bs->auth_opt->up) {
		if (!bfd_auth_opt_discr_ok(bs))
			return 0;

		key = bs->kc ? bfd_auth_opt_key_find_send(bs->kc) : NULL;
		if (key) {
			in.key_id = key->index;
			in.key = key->string;
		}
	} else if (bfd_auth_opt_keys_lost(bs)) {
		return 0;
	}

	return bfd_auth_opt_tx_build(bs->auth_opt, pkt, &in);
}

void bfd_auth_opt_session_sent(struct bfd_session *bs, const uint8_t *pkt)
{
	uint64_t hold = 0, interval;

	/*
	 * RFC 9985 has Up signalled in signed packets for a Detection Time
	 * first, which is taken from when the first of them goes out, and
	 * as the longer of the two directions'. That packet is sent from
	 * within the state machine, before detect_TO has caught up with the
	 * packet that brought the session up, so it is worked out here from
	 * what that packet said.
	 */
	if (!bs->auth_opt->up_sent) {
		interval = MAX(bs->xmt_TO,
			       MAX(bs->timers.desired_min_tx, bs->remote_timers.required_min_rx));
		hold = bfd_detection_timeout_us(bs->remote_detect_mult,
						bs->cur_timers.required_min_rx,
						bs->remote_timers.desired_min_tx);
		hold = MAX(MAX(hold, bs->detect_TO), bs->detect_mult * interval);
	}

	bs->auth_seq_num++;
	bfd_auth_opt_tx_commit(bs->auth_opt, bfd_auth_opt_now(), hold);

	bs->auth_opt_tx_mode = pkt[BFD_PKT_LEN + SEC_MODE];
	if (bs->auth_opt_tx_mode == BFD_AUTH_OPT_MODE_ISAAC)
		bs->stats.auth_opt_tx_isaac++;
	else
		bs->stats.auth_opt_tx_signed++;

	/* The Final is waited for from the first Poll that went out. */
	if (bs->auth_opt_reauth_phase == REAUTH_DUE &&
	    BFD_GETPBIT(((const struct bfd_pkt *)pkt)->flags))
		bfd_auth_opt_reauth_wait(bs, REAUTH_SENT);
}

const char *bfd_auth_opt_session_verify(struct bfd_session *bs, const struct bfd_pkt *cp)
{
	const uint8_t *pkt = (const uint8_t *)cp;
	const uint8_t *sec = pkt + BFD_PKT_LEN;
	struct bfd_auth_opt_rx in = {
		.local_up = bs->ses_state == PTM_BFD_UP,
		.last_seq = bs->auth_last_rx_seq_num,
	};
	enum bfd_auth_opt_result res;

	if (bs->auth_opt == NULL)
		return "not available to the session";
	if (!CHECK_FLAG(cp->flags, BFD_ABIT) || cp->len < BFD_PKT_LEN + BFD_AUTH_ISAAC_LEN) {
		bs->stats.auth_opt_rx_refused[BFD_AUTH_OPT_MALFORMED]++;
		return bfd_auth_opt_result_str(BFD_AUTH_OPT_MALFORMED);
	}

	if (in.local_up) {
		if (bfd_auth_opt_keys_lost(bs))
			return "a key the session came up with is gone";
	} else {
		/*
		 * As for the other kinds, nothing is taken while there is no
		 * key to answer with: the session could go up on a packet
		 * and have nothing to say so with.
		 */
		if (bs->kc == NULL || bfd_auth_opt_key_find_send(bs->kc) == NULL)
			return "no key to send with";

		if (!bfd_auth_opt_discr_ok(bs))
			return "no random discriminator to be had";
	}

	/*
	 * RFC 5880 Section 6.8.1: the sequence number is forgotten once
	 * nothing has arrived for twice the detection time. Not written
	 * back here, so that a packet that fails changes nothing.
	 */
	in.seq_known = bs->auth_seq_known &&
		       !(bs->detect_TO && monotime_since(&bs->auth_last_rx_time, NULL) >
						  (int64_t)(2 * bs->detect_TO));

	/* Only a signed packet can need a key that is not held already. */
	if (sec[SEC_MODE] == BFD_AUTH_OPT_MODE_MCI)
		in.key = bfd_auth_opt_accept_key(bs, sec[SEC_KEY_ID]);

	res = bfd_auth_opt_rx_verify(bs->auth_opt, pkt, cp->len, &in);
	if (res != BFD_AUTH_OPT_OK) {
		bs->stats.auth_opt_rx_refused[res]++;
		return bfd_auth_opt_result_str(res);
	}

	bs->auth_opt_rx_mode = sec[SEC_MODE];
	if (bs->auth_opt_rx_mode == BFD_AUTH_OPT_MODE_ISAAC)
		bs->stats.auth_opt_rx_isaac++;
	else
		bs->stats.auth_opt_rx_signed++;

	memcpy(&bs->auth_last_rx_seq_num, sec + 4, sizeof(bs->auth_last_rx_seq_num));
	bs->auth_last_rx_seq_num = ntohl(bs->auth_last_rx_seq_num);
	bs->auth_seq_known = true;
	monotime(&bs->auth_last_rx_time);
	bs->auth_opt_rx_key = in.key;
	return NULL;
}

void bfd_auth_opt_session_rcvd(struct bfd_session *bs, const struct bfd_pkt *cp)
{
	struct bfd_auth_opt_rx in = {
		.local_up = bs->ses_state == PTM_BFD_UP,
		.key = bs->auth_opt_rx_key,
	};
	bool pinned = bs->auth_opt->rx_key.set;

	bs->auth_opt_rx_key = NULL;
	bfd_auth_opt_rx_commit(bs->auth_opt, (const uint8_t *)cp, &in);

	/* Its lifetime may be the first to end, or be over already. */
	if (!pinned && bs->auth_opt->rx_key.set)
		bfd_auth_opt_keys_recheck(bs);

	/* A Final is always signed, so the peer has shown it has the key. */
	if (bs->auth_opt_reauth_phase != REAUTH_IDLE && bs->ses_state == PTM_BFD_UP &&
	    BFD_GETFBIT(cp->flags))
		bfd_auth_opt_reauth_idle(bs);
}
