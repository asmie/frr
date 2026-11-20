// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 9986 optimized MD5 meticulous keyed ISAAC authentication, with the
 * procedures of RFC 9985.
 *
 * Two endpoints run just enough of the BFD state machine to bring a
 * session up, and exchange packets through the code under test. What one
 * end builds is not only checked by the other: the Auth Keys are those of
 * RFC 9986 Section 10, further ones come from a separate Python
 * implementation of the generator, and the signed packet was computed
 * with Python's hashlib.
 *
 * Copyright (c) 2026 Piotr Olszewski
 */
#include <zebra.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/evp.h>
#endif

#include "bfdd/bfd_auth.h"

enum { ADMIN_DOWN, DOWN, INIT, UP };

#define POLL  0x20
#define FINAL 0x10

/* Offsets into a packet. */
#define FLAGS	 1
#define MULT	 2
#define LEN	 3
#define KEY_ID	 26
#define MODE	 27
#define SEQ	 28
#define SEED	 32
#define AUTH_KEY 36

#define MCI   BFD_AUTH_OPT_MODE_MCI
#define ISAAC BFD_AUTH_OPT_MODE_ISAAC

#define INTERVAL 300000ULL
#define HOLD	 (3 * INTERVAL)

/* The test inputs of RFC 9986 Section 10. */
#define RFC_KEY	  "RFC5880June"
#define RFC_SEED  0x0bfd5eed
#define RFC_YDISC 0x4002d15c

/* The stream those give, at the positions the tests look at. */
static const struct {
	uint32_t idx;
	uint32_t auth_key;
} rfc_stream[] = {
	{ 0, 0x9af65d83 },    { 1, 0x44355d56 },   { 2, 0x9334074e },	 { 3, 0xb643ef59 },
	{ 4, 0x74d659f1 },    { 5, 0x8966dc56 },   { 6, 0xa1f6f9bc },	 { 7, 0x21895a46 },
	{ 8, 0xd0e0919c },    { 255, 0x4e13bbfc }, { 256, 0xd413072c },	 { 257, 0x5b4725e8 },
	{ 511, 0xe3bf9c2a },  { 512, 0x0672b054 }, { 1000, 0x738f65c3 }, { 1535, 0x34582810 },
	{ 1536, 0x6b3805d9 },
};

struct ep {
	struct bfd_auth_opt opt;
	uint8_t state;
	uint8_t detect_mult;
	uint32_t my_discr, your_discr;
	/* bfd.XmitAuthSeq, bfd.AuthSeqKnown and bfd.RcvAuthSeq. */
	uint32_t tx_seq;
	bool seq_known;
	uint32_t rx_seq;
	/* The key it sends with and a second one it also accepts. */
	uint8_t key_id, key2_id;
	const char *key, *key2;
	bool have_seed;
	uint32_t seed;
	/* Sequence number of the first ISAAC format packet it sent. */
	bool isaac_sent;
	uint32_t isaac_first;
};

static uint64_t now = 1000000;

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

/* A is the end the RFC's inputs describe: its Seed, and B's discriminator. */
static void setup(struct ep *a, struct ep *b)
{
	static const struct ep init = {
		.state = DOWN, .detect_mult = 3, .key_id = 5, .key = RFC_KEY, .have_seed = true
	};

	*a = init;
	a->my_discr = 0x0a0b0c0d;
	a->seed = RFC_SEED;
	a->tx_seq = 1000;

	*b = init;
	b->my_discr = RFC_YDISC;
	b->seed = 0x5eed0b0b;
	b->tx_seq = 0x70000000;
}

static size_t ep_build(struct ep *ep, uint8_t *pkt, uint8_t flags)
{
	struct bfd_auth_opt_tx in = {
		.seq = ep->tx_seq + 1,
		.now = now,
		.key_id = ep->key_id,
		.key = ep->key,
	};

	memset(pkt, 0, BFD_AUTH_OPT_PKT_MAX);
	pkt[0] = 1 << 5;
	pkt[FLAGS] = ep->state << 6 | flags;
	pkt[MULT] = ep->detect_mult;
	put32(pkt + 4, ep->my_discr);
	put32(pkt + 8, ep->your_discr);
	put32(pkt + 12, 300000);
	put32(pkt + 16, 300000);
	put32(pkt + 20, 50000);

	return bfd_auth_opt_tx_build(&ep->opt, pkt, &in);
}

/* The packet just built went out. */
static void ep_sent(struct ep *ep, const uint8_t *pkt)
{
	ep->tx_seq++;
	if (pkt[MODE] == ISAAC && !ep->isaac_sent) {
		ep->isaac_sent = true;
		ep->isaac_first = ep->tx_seq;
	}
	bfd_auth_opt_tx_commit(&ep->opt, now, HOLD);
}

static size_t ep_send(struct ep *ep, uint8_t *pkt, uint8_t flags)
{
	size_t len = ep_build(ep, pkt, flags);

	assert(len == pkt[LEN]);
	assert(len == (pkt[MODE] == ISAAC ? 40 : 48));
	ep_sent(ep, pkt);
	return len;
}

static void ep_up(struct ep *ep)
{
	ep->state = UP;
	ep->isaac_sent = false;
	bfd_auth_opt_up(&ep->opt, ep->key_id, ep->key, ep->have_seed ? &ep->seed : NULL);
}

static enum bfd_auth_opt_result ep_recv(struct ep *ep, const uint8_t *pkt, size_t len)
{
	struct bfd_auth_opt_rx in = {
		.local_up = ep->state == UP,
		.seq_known = ep->seq_known,
		.last_seq = ep->rx_seq,
	};
	enum bfd_auth_opt_result res;
	uint8_t peer = pkt[FLAGS] >> 6;

	if (pkt[KEY_ID] == ep->key_id)
		in.key = ep->key;
	else if (ep->key2 && pkt[KEY_ID] == ep->key2_id)
		in.key = ep->key2;

	res = bfd_auth_opt_rx_verify(&ep->opt, pkt, len, &in);
	if (res != BFD_AUTH_OPT_OK)
		return res;

	ep->seq_known = true;
	ep->rx_seq = get32(pkt + SEQ);
	ep->your_discr = get32(pkt + 4);

	if (ep->state == DOWN && peer == DOWN) {
		ep->state = INIT;
	} else if ((ep->state == DOWN && peer == INIT) ||
		   (ep->state == INIT && (peer == INIT || peer == UP))) {
		ep_up(ep);
	} else if (ep->state == UP && peer <= DOWN) {
		ep->state = DOWN;
		bfd_auth_opt_reset(&ep->opt);
	}

	in.local_up = ep->state == UP;
	bfd_auth_opt_rx_commit(&ep->opt, pkt, &in);
	return BFD_AUTH_OPT_OK;
}

/* Send one packet across, which must be accepted. Returns its format. */
static uint8_t xfer(struct ep *from, struct ep *to, uint8_t flags)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	size_t len = ep_send(from, pkt, flags);

	assert(ep_recv(to, pkt, len) == BFD_AUTH_OPT_OK);
	return pkt[MODE];
}

static void exchange(struct ep *a, struct ep *b)
{
	xfer(a, b, 0);
	xfer(b, a, 0);
	now += INTERVAL;
}

static void bring_up(struct ep *a, struct ep *b)
{
	assert(xfer(a, b, 0) == MCI && b->state == INIT);
	assert(xfer(b, a, 0) == MCI && a->state == UP);
	assert(xfer(a, b, 0) == MCI && b->state == UP);
	assert(xfer(b, a, 0) == MCI);
	now += INTERVAL;
}

/* Exchange until both ends have moved to the ISAAC format. */
static void settle(struct ep *a, struct ep *b)
{
	int i;

	for (i = 0; i < 600; i++) {
		uint8_t ma = xfer(a, b, 0);
		uint8_t mb = xfer(b, a, 0);

		now += INTERVAL;
		if (ma == ISAAC && mb == ISAAC)
			return;
	}
	assert(!"the session never settled into the ISAAC format");
}

/*
 * Exchange until A has sent its first ISAAC format packet, which is left
 * in pkt and has not been delivered.
 */
static void first_isaac(struct ep *a, struct ep *b, uint8_t *pkt)
{
	int i;

	for (i = 0; i < 600; i++) {
		ep_send(a, pkt, 0);
		if (pkt[MODE] == ISAAC)
			return;
		assert(ep_recv(b, pkt, 48) == BFD_AUTH_OPT_OK);
		xfer(b, a, 0);
		now += INTERVAL;
	}
	assert(!"no ISAAC format packet was ever sent");
}

static void start(struct ep *a, struct ep *b)
{
	setup(a, b);
	bring_up(a, b);
	settle(a, b);
}

/*
 * Check a packet of A's against the stream, where its position in it is
 * one of those known. Returns whether it was.
 */
static bool check_rfc_stream(const struct ep *a, const uint8_t *pkt)
{
	uint32_t idx = get32(pkt + SEQ) - a->isaac_first;
	size_t i;

	if (pkt[MODE] != ISAAC)
		return false;

	assert(get32(pkt + SEED) == RFC_SEED);
	for (i = 0; i < array_size(rfc_stream); i++) {
		if (rfc_stream[i].idx == idx) {
			assert(get32(pkt + AUTH_KEY) == rfc_stream[i].auth_key);
			return true;
		}
	}
	return false;
}

/* A Down packet signed for key ID 5 and sequence number 0x01020304. */
static void test_signed_packet(void)
{
	static const uint8_t expected[48] = {
		0x20, 0x44, 0x03, 0x30, 0x0a, 0x0b, 0x0c, 0x0d, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x93, 0xe0, 0x00, 0x04, 0x93, 0xe0, 0x00, 0x00, 0xc3, 0x50,
		0x07, 0x18, 0x05, 0x01, 0x01, 0x02, 0x03, 0x04, 0x6a, 0xb8, 0x5c, 0xfb,
		0x2a, 0xda, 0xb7, 0x0b, 0x38, 0x68, 0x26, 0x09, 0x0c, 0x19, 0x90, 0xea,
	};
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;

	setup(&a, &b);
	a.tx_seq = 0x01020303;
	assert(ep_send(&a, pkt, 0) == sizeof(expected));
	assert(memcmp(pkt, expected, sizeof(expected)) == 0);
	assert(ep_recv(&b, expected, sizeof(expected)) == BFD_AUTH_OPT_OK);
	printf("signed packet: ok\n");
}

/* The eight Auth Keys of the RFC, in the packets that carry them. */
static void test_rfc_auth_keys(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	uint32_t seq;
	int i;

	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);

	seq = get32(pkt + SEQ);
	for (i = 0; i < 8; i++) {
		assert(pkt[MODE] == ISAAC && pkt[LEN] == 40 && pkt[25] == BFD_AUTH_ISAAC_LEN);
		assert(pkt[24] == BFD_AUTH_OPT_MD5 && pkt[KEY_ID] == 5);
		assert(get32(pkt + SEQ) == seq + i);
		assert(get32(pkt + SEED) == RFC_SEED);
		assert(get32(pkt + AUTH_KEY) == rfc_stream[i].auth_key);
		assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
		ep_send(&a, pkt, 0);
	}
	printf("RFC 9986 Auth Keys: ok\n");
}

/* Run long enough to cross six pages, checking A's stream on the way. */
static void test_page_flips(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i, checked = 0;

	start(&a, &b);
	for (i = 0; i < 1600; i++) {
		ep_send(&a, pkt, 0);
		checked += check_rfc_stream(&a, pkt);
		assert(ep_recv(&b, pkt, pkt[LEN]) == BFD_AUTH_OPT_OK);
		assert(xfer(&b, &a, 0) == ISAAC);
	}
	/* 255 to 257, 511, 512, 1000, 1535 and 1536 at the least. */
	assert(checked >= 8);
	printf("page flips: ok\n");
}

/* The sequence number wraps with the stream in use. */
static void test_wrap(void)
{
	struct ep a, b;
	int i;

	setup(&a, &b);
	a.tx_seq = 0xffffff00;
	b.tx_seq = 0xfffffff0;
	bring_up(&a, &b);
	settle(&a, &b);
	for (i = 0; i < 600; i++)
		exchange(&a, &b);
	assert(a.tx_seq < 0xffffff00 && b.tx_seq < 0xfffffff0);
	assert(xfer(&a, &b, 0) == ISAAC && xfer(&b, &a, 0) == ISAAC);
	printf("sequence wrap: ok\n");
}

static void test_signed_checks(void)
{
	uint8_t good[BFD_AUTH_OPT_PKT_MAX], pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;

	setup(&a, &b);
	xfer(&a, &b, 0);
	ep_send(&a, good, 0);

	/* A section or packet length the format does not have. */
	memcpy(pkt, good, sizeof(pkt));
	pkt[25]++;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_MALFORMED);
	assert(ep_recv(&b, good, 47) == BFD_AUTH_OPT_MALFORMED);
	assert(ep_recv(&b, good, 40) == BFD_AUTH_OPT_MALFORMED);

	/* A mode there is none of, and the other one at this length. */
	memcpy(pkt, good, sizeof(pkt));
	pkt[MODE] = 0;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_MALFORMED);
	pkt[MODE] = 3;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_MALFORMED);
	pkt[MODE] = ISAAC;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_MALFORMED);

	/* A key B does not have. */
	memcpy(pkt, good, sizeof(pkt));
	pkt[KEY_ID]++;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);

	/* Any other change breaks the digest. */
	memcpy(pkt, good, sizeof(pkt));
	pkt[MULT]++;
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_DIGEST);

	/* Meticulous: a repeat is refused, and so is too long a step. */
	assert(ep_recv(&b, good, 48) == BFD_AUTH_OPT_OK);
	assert(ep_recv(&b, good, 48) == BFD_AUTH_OPT_SEQUENCE);
	a.tx_seq += 9;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_SEQUENCE);
	a.tx_seq -= 2;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_OK);

	/* With no sequence number known, whatever comes signed is taken. */
	b.seq_known = false;
	a.tx_seq += 100000;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_OK);
	printf("signed packet checks: ok\n");
}

/*
 * An ISAAC format packet is only taken for a repeat of the last signed
 * Up packet. Each thing wrong with one must be refused and leave the
 * session able to accept the packet as it was sent.
 */
static void test_isaac_checks(void)
{
	uint8_t good[BFD_AUTH_OPT_PKT_MAX], pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b, c, d;
	unsigned int byte, bit;

	start(&a, &b);
	ep_send(&a, good, 0);
	assert(good[MODE] == ISAAC);

	/*
	 * Every bit of the header: state, Poll, Final, Detect Mult, the
	 * discriminators and the intervals all need a signed packet.
	 */
	for (byte = 0; byte < 24; byte++) {
		for (bit = 0; bit < 8; bit++) {
			memcpy(pkt, good, sizeof(pkt));
			pkt[byte] ^= 1 << bit;
			assert(ep_recv(&b, pkt, pkt[LEN]) ==
			       (byte == LEN ? BFD_AUTH_OPT_MALFORMED : BFD_AUTH_OPT_NEEDS_MCI));
		}
	}

	memcpy(pkt, good, sizeof(pkt));
	pkt[25]--;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_MALFORMED);

	memcpy(pkt, good, sizeof(pkt));
	pkt[KEY_ID]++;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_KEY_ID);

	memcpy(pkt, good, sizeof(pkt));
	pkt[SEED] ^= 1;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_SEED);

	memcpy(pkt, good, sizeof(pkt));
	pkt[AUTH_KEY + 3] ^= 1;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);

	/* The Auth Key of another sequence number, and one out of the window. */
	memcpy(pkt, good, sizeof(pkt));
	put32(pkt + SEQ, get32(good + SEQ) + 1);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	put32(pkt + SEQ, get32(good + SEQ) + 9);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_SEQUENCE);

	/* A session that is not up takes none, even one that was not reset. */
	setup(&c, &d);
	assert(ep_recv(&d, good, 40) == BFD_AUTH_OPT_NEEDS_MCI);
	b.state = DOWN;
	assert(ep_recv(&b, good, 40) == BFD_AUTH_OPT_NEEDS_MCI);
	b.state = UP;

	/* After all that, the packet itself, once. */
	assert(ep_recv(&b, good, 40) == BFD_AUTH_OPT_OK);
	assert(ep_recv(&b, good, 40) == BFD_AUTH_OPT_SEQUENCE);
	exchange(&a, &b);
	printf("ISAAC format checks: ok\n");
}

/*
 * What an ISAAC format packet repeats is a signed Up packet. A signed
 * packet in another state takes that away until Up is signed again.
 */
static void test_reference(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b, c, d;

	/* D came up on C's Init: C has not said Up yet. */
	setup(&c, &d);
	xfer(&d, &c, 0);
	xfer(&c, &d, 0);
	assert(d.state == UP && !d.opt.rx_ref_valid && !d.opt.peer_up);

	start(&a, &b);

	/* A signs a packet that says Init. B stays up but stops trusting. */
	a.state = INIT;
	assert(xfer(&a, &b, 0) == MCI && b.state == UP);
	a.state = UP;
	ep_send(&a, pkt, 0);
	assert(pkt[MODE] == ISAAC);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_NEEDS_MCI);

	/* Until A signs Up again, here as a Poll. */
	assert(xfer(&a, &b, POLL) == MCI);
	assert(xfer(&b, &a, FINAL) == MCI);
	settle(&a, &b);
	printf("reference packet: ok\n");
}

/*
 * A change, a Poll and a Final are signed, and so are the packets after
 * them until the peer has had Detect Mult chances to see what was said.
 */
static void test_changes_are_signed(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	start(&a, &b);

	/* Detect Mult itself changes: four signed packets, the new value. */
	a.detect_mult = 4;
	for (i = 0; i < 4; i++)
		assert(xfer(&a, &b, 0) == MCI);
	assert(xfer(&a, &b, 0) == ISAAC);

	/* A Poll, then four more without it. */
	assert(xfer(&a, &b, POLL) == MCI);
	for (i = 0; i < 4; i++)
		assert(xfer(&a, &b, 0) == MCI);
	assert(xfer(&a, &b, 0) == ISAAC);

	/*
	 * Should B see the Poll and none of what follows it, the Poll is
	 * still Up signed, and the packets after it repeat it but for that
	 * bit.
	 */
	ep_send(&a, pkt, POLL);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_OK);
	for (i = 0; i < 5; i++)
		ep_send(&a, pkt, 0);
	assert(pkt[MODE] == ISAAC);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);

	/* B answers with a Final and goes through the same on its side. */
	assert(xfer(&b, &a, FINAL) == MCI);
	for (i = 0; i < 3; i++)
		assert(xfer(&b, &a, 0) == MCI);
	assert(xfer(&b, &a, 0) == ISAAC);

	/* The peer's discriminator changing is a change of our header too. */
	b.my_discr++;
	assert(xfer(&b, &a, 0) == MCI);
	assert(xfer(&a, &b, 0) == MCI);
	settle(&a, &b);

	/*
	 * Detect Mult comes down from four. B allows for losses by the old
	 * value until it hears the new one, so that is how many are signed.
	 */
	a.detect_mult = 2;
	for (i = 0; i < 4; i++)
		assert(xfer(&a, &b, 0) == MCI);
	assert(xfer(&a, &b, 0) == ISAAC);

	/* Lowered twice in a row, B may still be going by the first: five. */
	a.detect_mult = 5;
	settle(&a, &b);
	a.detect_mult = 3;
	assert(xfer(&a, &b, 0) == MCI);
	a.detect_mult = 2;
	for (i = 0; i < 4; i++)
		assert(xfer(&a, &b, 0) == MCI);
	assert(xfer(&a, &b, 0) == ISAAC);
	printf("changes are signed: ok\n");
}

/*
 * The generator is seeded with the first packet that uses it. A peer that
 * changed its discriminator after the session came up reads the new one
 * off that packet, so that is the one the stream has to be made from.
 */
static void test_discriminator_change(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;

	setup(&a, &b);
	bring_up(&a, &b);
	b.my_discr = RFC_YDISC + 1;
	first_isaac(&a, &b, pkt);
	assert(get32(pkt + 8) == RFC_YDISC + 1);
	assert(get32(pkt + AUTH_KEY) == 0xab350fb4);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	printf("discriminator change: ok\n");
}

/*
 * Up is signalled in signed packets for the hold time, counted from the
 * first Up packet that went out, and until the peer has signed Up too.
 */
static void test_hold(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	uint64_t first_up;
	int i;

	setup(&a, &b);
	xfer(&a, &b, 0);
	xfer(&b, &a, 0);
	assert(a.state == UP);

	/* A's first Up packet is built but never leaves. Time passes. */
	assert(ep_build(&a, pkt, 0) == 48);
	now += 10 * HOLD;
	assert(!a.opt.up_sent);

	first_up = now;
	xfer(&a, &b, 0);
	xfer(&b, &a, 0);
	assert(a.opt.peer_up && a.opt.hold_until == first_up + HOLD);

	/* Past the burst, yet still signed while the hold lasts. */
	for (i = 0; i < 10; i++)
		assert(xfer(&a, &b, 0) == MCI);
	now = first_up + HOLD - 1;
	assert(xfer(&a, &b, 0) == MCI);
	now = first_up + HOLD;
	assert(xfer(&a, &b, 0) == ISAAC);

	/* The peer not having signed Up holds it back just the same. */
	setup(&a, &b);
	xfer(&a, &b, 0);
	xfer(&b, &a, 0);
	now += 10 * HOLD;
	for (i = 0; i < 10; i++) {
		assert(xfer(&a, &b, 0) == MCI);
		now += HOLD;
	}
	assert(!a.opt.peer_up);
	printf("hold: ok\n");
}

/* Without a Seed one end keeps signing. The other need not. */
static void test_no_seed(void)
{
	struct ep a, b;
	int i;

	setup(&a, &b);
	b.have_seed = false;
	bring_up(&a, &b);
	for (i = 0; i < 20; i++)
		exchange(&a, &b);
	assert(xfer(&a, &b, 0) == ISAAC);
	assert(xfer(&b, &a, 0) == MCI);
	printf("no Seed: ok\n");
}

/*
 * A packet that was built and not sent takes nothing with it: the next
 * one is the same packet again.
 */
static void test_failed_send(void)
{
	uint8_t lost[BFD_AUTH_OPT_PKT_MAX], pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	setup(&a, &b);
	bring_up(&a, &b);

	/* The very first ISAAC format packet, which is what seeds the stream. */
	for (i = 0; i < 20; i++) {
		assert(ep_build(&a, lost, 0));
		if (lost[MODE] == ISAAC)
			break;
		ep_sent(&a, lost);
		assert(ep_recv(&b, lost, lost[LEN]) == BFD_AUTH_OPT_OK);
		xfer(&b, &a, 0);
		now += INTERVAL;
	}
	assert(lost[MODE] == ISAAC && !a.opt.tx_live);
	assert(get32(lost + AUTH_KEY) == rfc_stream[0].auth_key);
	ep_send(&a, pkt, 0);
	assert(memcmp(pkt, lost, 40) == 0);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);

	/* The last packet of a page. */
	do {
		xfer(&b, &a, 0);
		ep_send(&a, pkt, 0);
		assert(ep_recv(&b, pkt, pkt[LEN]) == BFD_AUTH_OPT_OK);
	} while (get32(pkt + SEQ) - a.isaac_first != 254);

	assert(ep_build(&a, lost, 0) == 40);
	assert(get32(lost + AUTH_KEY) == 0x4e13bbfc);
	ep_send(&a, pkt, 0);
	assert(memcmp(pkt, lost, 40) == 0);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);

	/* And the first of the next. */
	ep_send(&a, pkt, 0);
	assert(get32(pkt + AUTH_KEY) == 0xd413072c);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	printf("failed send: ok\n");
}

/* Packets lost on the way are stepped over, within the window. */
static void test_loss(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX], late[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	/* The first ISAAC format packets of all: RFC 9986 Section 10.2. */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	for (i = 0; i < 5; i++)
		ep_send(&a, pkt, 0);
	assert(get32(pkt + AUTH_KEY) == rfc_stream[5].auth_key);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	exchange(&a, &b);

	/* Across the end of a page: 253 to 258 never arrive. */
	do {
		ep_send(&a, pkt, 0);
		assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	} while (get32(pkt + SEQ) - a.isaac_first != 252);
	for (i = 0; i < 7; i++)
		ep_send(&a, pkt, 0);
	assert(get32(pkt + SEQ) - a.isaac_first == 259);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	exchange(&a, &b);

	/* More than the window allows is not stepped over. */
	for (i = 0; i < 10; i++)
		ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_SEQUENCE);

	/*
	 * As many as there are before the end of the stream's first page,
	 * where the first packet to arrive has to be.
	 */
	setup(&a, &b);
	a.detect_mult = b.detect_mult = 255;
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	for (i = 0; i < 255; i++)
		ep_send(&a, pkt, 0);
	ep_send(&a, late, 0);
	assert(ep_recv(&b, late, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	assert(ep_recv(&b, late, 40) == BFD_AUTH_OPT_OK);
	printf("loss: ok\n");
}

/*
 * RFC 9986 Section 10.2 takes the first number of a stream to belong to
 * the sequence number the receiver expects next. It does not when signed
 * packets just before it were lost, or when a signed packet arrives after
 * the first ISAAC ones were lost. The receiver makes up for both by
 * looking anywhere the stream could have started this time up, and for
 * the second at the cost of one more packet.
 */
static void test_first_packet_misplaced(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	/*
	 * B never saw the last signed packet, so the stream starts one
	 * sequence number after the one RFC 9986 Section 10.2 has B expect
	 * it at. B finds the number a place back and goes on from there,
	 * over a page and more.
	 */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	b.rx_seq--;
	b.opt.rx_last_seq--;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	assert(b.opt.rx_live && b.opt.rx_base == a.isaac_first);
	for (i = 0; i < 300; i++)
		assert(xfer(&a, &b, 0) == ISAAC);

	/* Two signed packets lost, and the first of the stream with them. */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	b.rx_seq -= 2;
	b.opt.rx_last_seq -= 2;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	assert(b.opt.rx_live && b.opt.rx_base == a.isaac_first);
	assert(xfer(&a, &b, 0) == ISAAC);

	/*
	 * The first ISAAC ones are lost and signed packets follow, so the
	 * stream started before the packet B took last. B goes by its
	 * having started this time up, and finds the number, but that far
	 * back there are many places for one to turn up in: the packet is
	 * let go, and the stream is taken up when the next bears it out.
	 */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	ep_send(&a, pkt, 0);
	assert(xfer(&a, &b, POLL) == MCI);
	for (i = 0; i < 3; i++)
		assert(xfer(&a, &b, 0) == MCI);
	ep_send(&a, pkt, 0);
	assert(pkt[MODE] == ISAAC);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(!b.opt.rx_live);

	/* The same number again, on the next sequence number, does not. */
	put32(pkt + SEQ, get32(pkt + SEQ) + 1);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(!b.opt.rx_live);

	/* That put B off, so it takes A two more to be believed. */
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(xfer(&a, &b, 0) == ISAAC);
	assert(b.opt.rx_live && b.opt.rx_base == a.isaac_first);
	for (i = 0; i < 300; i++)
		assert(xfer(&a, &b, 0) == ISAAC);

	/*
	 * The sequence number has gone all the way round with only signed
	 * packets seen, so the stream's first packet has the number of the
	 * first packet of this time up.
	 */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	b.opt.rx_first_seq = get32(pkt + SEQ);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	assert(b.opt.rx_live && b.opt.rx_base == a.isaac_first);

	/*
	 * A number from further into the stream than there have been
	 * sequence numbers this time up is not looked for.
	 */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	for (i = 0; i < 50; i++)
		ep_send(&a, pkt, 0);
	put32(pkt + SEQ, a.isaac_first);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(!b.opt.rx_live);

	/*
	 * Nor one from beyond the first page. All of that went by unseen,
	 * signed packets apart, and the stream stays out of reach: it never
	 * checks out and only signed packets get through.
	 */
	setup(&a, &b);
	a.detect_mult = b.detect_mult = 255;
	bring_up(&a, &b);
	first_isaac(&a, &b, pkt);
	for (i = 0; i < 300; i++)
		ep_send(&a, pkt, 0);
	assert(xfer(&a, &b, POLL) == MCI);
	for (i = 0; i < 300; i++) {
		ep_send(&a, pkt, 0);
		if (pkt[MODE] == ISAAC)
			break;
		assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_OK);
	}
	assert(pkt[MODE] == ISAAC);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_AUTH_KEY);
	assert(!b.opt.rx_live);
	printf("misplaced first packet: ok\n");
}

/*
 * The sequence number goes on through signed packets and the generator
 * has to follow: RFC 9986 Section 12.
 */
static void test_signed_stretch(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i, round;

	/* A Polls for more than two pages. Its stream is where it should be. */
	start(&a, &b);
	do {
		assert(xfer(&a, &b, POLL) == MCI);
		assert(xfer(&b, &a, 0) == ISAAC);
	} while (a.tx_seq - a.isaac_first < 990);
	do {
		ep_send(&a, pkt, 0);
		check_rfc_stream(&a, pkt);
		assert(ep_recv(&b, pkt, pkt[LEN]) == BFD_AUTH_OPT_OK);
	} while (get32(pkt + SEQ) - a.isaac_first != 1000);
	assert(pkt[MODE] == ISAAC);

	/*
	 * The widest step a signed packet may take, 3 * 255, from two
	 * places in a page: 764 packets that B never sees, then a Poll.
	 * B's generator has to make up the pages in between.
	 */
	setup(&a, &b);
	a.detect_mult = b.detect_mult = 255;
	bring_up(&a, &b);
	settle(&a, &b);
	for (round = 0; round < 2; round++) {
		for (i = 0; i < 764; i++)
			ep_send(&a, pkt, 0);
		assert(xfer(&a, &b, POLL) == MCI);
		settle(&a, &b);
		assert(b.opt.rx_live);
	}

	/* One more than that is outside any window. */
	for (i = 0; i < 765; i++)
		ep_send(&a, pkt, 0);
	ep_send(&a, pkt, POLL);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_SEQUENCE);
	printf("signed stretch: ok\n");
}

/*
 * A sequence number picked up from nothing, as after it has aged out,
 * can be anywhere. The stream is given up rather than guessed at, and a
 * new Seed does not bring it back.
 */
static void test_stream_lost(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	start(&a, &b);
	for (i = 0; i < 5000; i++)
		ep_send(&a, pkt, 0);
	b.seq_known = false;
	assert(xfer(&a, &b, POLL) == MCI);
	assert(b.opt.rx_lost && !b.opt.rx_live);

	for (i = 0; i < 4; i++)
		ep_send(&a, pkt, 0);
	assert(pkt[MODE] == ISAAC);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_NEEDS_MCI);
	pkt[SEED] ^= 1;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_NEEDS_MCI);

	/* Signed packets still get through, and B's own stream is unharmed. */
	assert(xfer(&a, &b, POLL) == MCI);
	assert(xfer(&b, &a, 0) == ISAAC);
	printf("stream lost: ok\n");
}

/*
 * A session stays with the keys it came up with, one for each direction,
 * and which they are is open until then.
 */
static void test_keys(void)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;
	int i;

	/* A sends with key 5 and B with key 9; each has both. */
	setup(&a, &b);
	a.key2_id = 9;
	a.key2 = "another-key";
	b.key_id = 9;
	b.key = "another-key";
	b.key2_id = 5;
	b.key2 = RFC_KEY;
	bring_up(&a, &b);
	settle(&a, &b);

	/* Only a signed packet may come with another key, whatever it says. */
	ep_build(&a, pkt, 0);
	assert(pkt[MODE] == ISAAC);
	pkt[KEY_ID] = 9;
	pkt[FLAGS] = INIT << 6 | 0x04;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_KEY_ID);
	pkt[FLAGS] = DOWN << 6 | 0x04;
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_KEY_ID);

	/* A moves to key 9, which B has: signed correctly, and refused. */
	a.opt.tx_key.id = 9;
	strlcpy(a.opt.tx_key.secret, "another-key", sizeof(a.opt.tx_key.secret));
	ep_send(&a, pkt, POLL);
	assert(pkt[MODE] == MCI && pkt[KEY_ID] == 9);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);

	/*
	 * A goes down, as it must to change keys, and says so with the new
	 * one. That B takes, or it would be left waiting for a timeout. Not
	 * with a key it does not have, though.
	 */
	a.state = DOWN;
	bfd_auth_opt_reset(&a.opt);
	a.key_id = 7;
	a.key = "unknown-to-b";
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);
	a.key_id = 9;
	a.key = "another-key";

	/* Init would leave B up, so that is not let through either. */
	a.state = INIT;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);
	a.state = DOWN;
	assert(xfer(&a, &b, 0) == MCI && b.state == DOWN);

	/*
	 * The same when the ID was kept and only the secret changed, here
	 * with AdminDown. Up and Init are still held to the secret the
	 * session came up with.
	 */
	setup(&a, &b);
	bring_up(&a, &b);
	settle(&a, &b);
	a.key = b.key = "changed-secret";
	strlcpy(a.opt.tx_key.secret, a.key, sizeof(a.opt.tx_key.secret));
	ep_send(&a, pkt, POLL);
	assert(pkt[KEY_ID] == 5);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_DIGEST);
	bfd_auth_opt_reset(&a.opt);
	a.state = INIT;
	ep_send(&a, pkt, 0);
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_DIGEST);
	a.state = ADMIN_DOWN;
	assert(xfer(&a, &b, 0) == MCI && b.state == DOWN);

	/*
	 * And the other way about: B's key was changed, or taken away, and
	 * A goes down still signing with the one the session came up with.
	 */
	for (i = 0; i < 2; i++) {
		setup(&a, &b);
		bring_up(&a, &b);
		settle(&a, &b);
		b.key = i ? NULL : "changed-secret";
		a.state = DOWN;
		bfd_auth_opt_reset(&a.opt);
		assert(xfer(&a, &b, 0) == MCI && b.state == DOWN);
	}

	/* A configured key too short to count is no second chance. */
	setup(&a, &b);
	bring_up(&a, &b);
	settle(&a, &b);
	b.key = "sevenby";
	a.state = DOWN;
	bfd_auth_opt_reset(&a.opt);
	ep_send(&a, pkt, 0);
	assert(bfd_auth_md5_sign(pkt, 48, "sevenby"));
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_DIGEST);

	/* Before the session is up there is nothing to stay with. */
	setup(&a, &b);
	b.key2_id = 9;
	b.key2 = "another-key";
	xfer(&a, &b, 0);
	a.key_id = 9;
	a.key = "another-key";
	assert(xfer(&a, &b, 0) == MCI);

	/* Seven bytes are too few and seventeen too many, either way. */
	setup(&a, &b);
	ep_send(&a, pkt, 0);
	b.key = "sevenby";
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);
	b.key = "seventeenbytekey1";
	assert(ep_recv(&b, pkt, 48) == BFD_AUTH_OPT_KEY_ID);
	a.key = "sevenby";
	assert(ep_build(&a, pkt, 0) == 0);
	a.key = "seventeenbytekey1";
	assert(ep_build(&a, pkt, 0) == 0);
	a.key = NULL;
	assert(ep_build(&a, pkt, 0) == 0);
	printf("keys: ok\n");
}

/*
 * A packet of an earlier session, made out to be the next one of this
 * session: the header and sequence number are unsigned and so are easy
 * to get right, which leaves the Seed and Auth Key to be told apart.
 */
static void replay(struct ep *from, struct ep *to, uint8_t *old)
{
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];

	ep_build(from, pkt, 0);
	memcpy(old, pkt, 24);
	old[LEN] = 40;
	put32(old + SEQ, to->rx_seq + 1);
}

/*
 * Going down leaves nothing behind, and the next time up is a session of
 * its own: new Seeds, and new discriminators, which is what keeps the
 * first ISAAC format packets of the last time up from passing again.
 */
static void test_restart(void)
{
	static const struct bfd_auth_opt zero;
	uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
	uint8_t old_a[BFD_AUTH_OPT_PKT_MAX], old_b[BFD_AUTH_OPT_PKT_MAX];
	struct ep a, b;

	/* Keep the first number of each stream. */
	setup(&a, &b);
	bring_up(&a, &b);
	first_isaac(&a, &b, old_a);
	assert(ep_recv(&b, old_a, 40) == BFD_AUTH_OPT_OK);
	first_isaac(&b, &a, old_b);
	assert(get32(old_b + SEQ) == b.isaac_first);
	assert(ep_recv(&a, old_b, 40) == BFD_AUTH_OPT_OK);

	a.state = DOWN;
	bfd_auth_opt_reset(&a.opt);
	assert(memcmp(&a.opt, &zero, sizeof(zero)) == 0);
	assert(xfer(&a, &b, 0) == MCI && b.state == DOWN);
	assert(memcmp(&b.opt, &zero, sizeof(zero)) == 0);

	a.my_discr++;
	a.seed = 0x12345678;
	b.my_discr++;
	b.seed = 0x9abcdef0;
	bring_up(&a, &b);
	replay(&a, &b, old_a);
	assert(ep_recv(&b, old_a, 40) == BFD_AUTH_OPT_AUTH_KEY);
	replay(&b, &a, old_b);
	assert(ep_recv(&a, old_b, 40) == BFD_AUTH_OPT_AUTH_KEY);

	first_isaac(&a, &b, pkt);
	assert(get32(pkt + SEED) == 0x12345678);
	assert(get32(pkt + AUTH_KEY) != rfc_stream[0].auth_key);
	assert(ep_recv(&b, pkt, 40) == BFD_AUTH_OPT_OK);
	first_isaac(&b, &a, pkt);
	assert(get32(pkt + SEED) == 0x9abcdef0);
	assert(ep_recv(&a, pkt, 40) == BFD_AUTH_OPT_OK);
	printf("restart: ok\n");
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
	/* A FIPS provider refuses MD5, and with it the signed format. */
	if (!md5_available()) {
		uint8_t pkt[BFD_AUTH_OPT_PKT_MAX];
		struct ep a, b;

		setup(&a, &b);
		assert(ep_build(&a, pkt, 0) == 0);
		printf("MD5 refused by the crypto provider: nothing can be signed\n");
		return 0;
	}

	test_signed_packet();
	test_rfc_auth_keys();
	test_page_flips();
	test_wrap();
	test_signed_checks();
	test_isaac_checks();
	test_reference();
	test_changes_are_signed();
	test_discriminator_change();
	test_hold();
	test_no_seed();
	test_failed_send();
	test_loss();
	test_first_packet_misplaced();
	test_signed_stretch();
	test_stream_lost();
	test_keys();
	test_restart();
	return 0;
}
