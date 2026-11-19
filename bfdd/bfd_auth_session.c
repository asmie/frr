// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 9986 optimized authentication as a session sees it: which sessions
 * may use it, and with which keys.
 *
 * Copyright (c) 2026 Piotr Olszewski
 */

#include <zebra.h>

#include "bfd.h"
#include "bfd_auth.h"

/* An MD5 key of a length the type takes, with an ID that fits the packet. */
static bool bfd_auth_opt_key_fits(const struct key *key)
{
	size_t len;

	if (key->hash_algo != KEYCHAIN_ALGO_MD5 || key->string == NULL || key->index > UINT8_MAX)
		return false;

	len = strlen(key->string);
	return len >= BFD_AUTH_OPT_KEY_MIN_LEN && len <= BFD_AUTH_MD5_KEY_MAX_LEN;
}

struct key *bfd_auth_opt_key_find_send(const struct keychain *kc)
{
	struct listnode *node;
	struct key *key;
	time_t now = time(NULL);

	/* The lifetime as lib/keychain reads it: no start, no lifetime. */
	for (ALL_LIST_ELEMENTS_RO(kc->key, node, key)) {
		if (!bfd_auth_opt_key_fits(key))
			continue;
		if (key->send.start == 0 ||
		    (key->send.start <= now && (key->send.end >= now || key->send.end == -1)))
			return key;
	}
	return NULL;
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
