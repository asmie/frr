// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ISAAC pseudorandom number generator, for RFC 9986 authentication.
 *
 * The algorithm is Bob Jenkins' ISAAC, which he placed in the public
 * domain: https://www.burtleburtle.net/bob/rand/isaac.html
 *
 * Copyright (c) 2026 Piotr Olszewski
 */

#include <zebra.h>

#include "bfd_isaac.h"

/* clang-format off */
#define MIX(a, b, c, d, e, f, g, h)                                                               \
	do {                                                                                      \
		a ^= b << 11; d += a; b += c;                                                     \
		b ^= c >> 2;  e += b; c += d;                                                     \
		c ^= d << 8;  f += c; d += e;                                                     \
		d ^= e >> 16; g += d; e += f;                                                     \
		e ^= f << 10; h += e; f += g;                                                     \
		f ^= g >> 4;  a += f; g += h;                                                     \
		g ^= h << 8;  b += g; h += a;                                                     \
		h ^= a >> 9;  c += h; a += b;                                                     \
	} while (0)
/* clang-format on */

/* One result. The state is read and written in place, as the original does. */
#define STEP(i, shifted)                                                                          \
	do {                                                                                      \
		x = mem[i];                                                                       \
		a = (a ^ (shifted)) + mem[((i) + BFD_ISAAC_PAGE / 2) % BFD_ISAAC_PAGE];           \
		mem[i] = y = mem[(x >> 2) % BFD_ISAAC_PAGE] + a + b;                              \
		rsl[i] = b = mem[(y >> 10) % BFD_ISAAC_PAGE] + x;                                 \
	} while (0)

void bfd_isaac_next_page(struct bfd_isaac *ctx)
{
	uint32_t *mem = ctx->mem, *rsl = ctx->rsl;
	uint32_t a = ctx->a, b = ctx->b + ++ctx->c;
	uint32_t x, y;
	unsigned int i;

	for (i = 0; i < BFD_ISAAC_PAGE; i += 4) {
		STEP(i, a << 13);
		STEP(i + 1, a >> 6);
		STEP(i + 2, a << 2);
		STEP(i + 3, a >> 16);
	}

	ctx->a = a;
	ctx->b = b;
}

void bfd_isaac_init(struct bfd_isaac *ctx, const uint8_t seed[BFD_ISAAC_SEED_LEN])
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t *mem = ctx->mem, *rsl = ctx->rsl;
	unsigned int i, pass;

	/*
	 * The seed bytes are taken as little endian words whatever the
	 * host is: that is what reproduces the RFC 9986 test vectors.
	 */
	for (i = 0; i < BFD_ISAAC_PAGE; i++, seed += 4)
		rsl[i] = (uint32_t)seed[0] | (uint32_t)seed[1] << 8 | (uint32_t)seed[2] << 16 |
			 (uint32_t)seed[3] << 24;

	a = b = c = d = e = f = g = h = 0x9e3779b9; /* the golden ratio */
	for (i = 0; i < 4; i++)
		MIX(a, b, c, d, e, f, g, h);

	/* Fold the seed in, then once more so all of it reaches all of mem. */
	for (pass = 0; pass < 2; pass++) {
		const uint32_t *src = pass == 0 ? rsl : mem;

		for (i = 0; i < BFD_ISAAC_PAGE; i += 8) {
			a += src[i];
			b += src[i + 1];
			c += src[i + 2];
			d += src[i + 3];
			e += src[i + 4];
			f += src[i + 5];
			g += src[i + 6];
			h += src[i + 7];
			MIX(a, b, c, d, e, f, g, h);
			mem[i] = a;
			mem[i + 1] = b;
			mem[i + 2] = c;
			mem[i + 3] = d;
			mem[i + 4] = e;
			mem[i + 5] = f;
			mem[i + 6] = g;
			mem[i + 7] = h;
		}
	}

	ctx->a = ctx->b = ctx->c = 0;
	bfd_isaac_next_page(ctx);
}

bool bfd_isaac_seed(struct bfd_isaac *ctx, uint32_t seed, uint32_t your_discr, const uint8_t *key,
		    size_t keylen)
{
	uint8_t buf[BFD_ISAAC_SEED_LEN];
	size_t reclen = 8 + keylen + 1;
	size_t off, n;
	uint8_t counter = 0;

	if (key == NULL || keylen == 0 || keylen > BFD_ISAAC_KEY_MAX)
		return false;

	/*
	 * RFC 9986 Section 10: the buffer is filled with copies of Seed,
	 * Your Discriminator, the key and a counter that numbers the copy,
	 * the last copy being cut off where the buffer ends.
	 */
	seed = htonl(seed);
	your_discr = htonl(your_discr);
	memcpy(buf, &seed, 4);
	memcpy(buf + 4, &your_discr, 4);
	memcpy(buf + 8, key, keylen);
	buf[reclen - 1] = 0;

	for (off = reclen; off < sizeof(buf); off += n) {
		n = MIN(reclen, sizeof(buf) - off);
		memcpy(buf + off, buf, n);
		if (n == reclen)
			buf[off + n - 1] = ++counter;
	}

	bfd_isaac_init(ctx, buf);
	explicit_bzero(buf, sizeof(buf));
	return true;
}
