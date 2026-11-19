// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Piotr Olszewski */
#ifndef _BFDD_ISAAC_H
#define _BFDD_ISAAC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * ISAAC as RFC 9986 uses it: seeded once per session direction, it hands
 * out pages of 256 Auth Keys, one for each sequence number.
 *
 * RFC 9986 Section 15.1 calls ISAAC unsuitable for anything else, so this
 * lives with bfdd rather than in libfrr.
 */
#define BFD_ISAAC_PAGE	   256
#define BFD_ISAAC_SEED_LEN (BFD_ISAAC_PAGE * 4)
/* Longest key that fits the seed next to its 9 bytes of framing. */
#define BFD_ISAAC_KEY_MAX (BFD_ISAAC_SEED_LEN - 9)

struct bfd_isaac {
	/* The current page. Everything else is the generator's own state. */
	uint32_t rsl[BFD_ISAAC_PAGE];
	uint32_t mem[BFD_ISAAC_PAGE];
	uint32_t a, b, c;
};

/* Seed from a full seed buffer and produce the first page. */
void bfd_isaac_init(struct bfd_isaac *ctx, const uint8_t seed[BFD_ISAAC_SEED_LEN]);

/*
 * Seed as RFC 9986 Section 10 lays it out, from the Seed and the Your
 * Discriminator the packets carry and from the secret key, and produce
 * the first page. Fails for an empty key or one too long to fit.
 */
bool bfd_isaac_seed(struct bfd_isaac *ctx, uint32_t seed, uint32_t your_discr, const uint8_t *key,
		    size_t keylen);

/* Replace the current page with the one that follows it. */
void bfd_isaac_next_page(struct bfd_isaac *ctx);

#endif /* _BFDD_ISAAC_H */
