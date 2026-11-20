#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# bfd_isaac_peer.py
# Part of NetDEF Topology Tests
#

"""
A BFD speaker for the optimized MD5 meticulous keyed ISAAC authentication
of RFC 9986, written without reference to bfdd's code for it.

It does two things two routers running bfdd cannot do for each other. It
checks everything bfdd sends against its own MD5 and its own ISAAC: every
digest, every Auth Key, the sequence numbers, and that a packet in the
ISAAC format only ever repeats the last signed one. And it can misbehave:
send packets no implementation would, or leave a Poll without its Final.

The generator is Bob Jenkins' ISAAC, seeded as RFC 9986 Section 10 lays
out, and can be told apart from a wrong one with the vectors of that
section: see --self-test.

Standard library only. Prints one line of JSON when it is done.
"""

import argparse
import hashlib
import json
import os
import select
import socket
import struct
import sys
import time

M32 = 0xFFFFFFFF

ADMIN_DOWN, DOWN, INIT, UP = 0, 1, 2, 3
STATE_NAME = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}

FLAG_POLL = 0x20
FLAG_FINAL = 0x10
FLAG_AUTH = 0x04

AUTH_TYPE = 7
MODE_SIGNED = 1
MODE_ISAAC = 2

BFD_PORT = 3784
BFD_SOURCE_PORT = 49152


class Isaac:
    "ISAAC, giving its numbers a page of 256 at a time."

    def __init__(self, seed):
        self.rsl = list(struct.unpack("<256I", seed))
        self.mem = [0] * 256
        self.a = self.b = self.c = 0
        s = [0x9E3779B9] * 8
        for _ in range(4):
            s = self._mix(s)
        for src in (self.rsl, self.mem):
            for i in range(0, 256, 8):
                s = self._mix([(s[j] + src[i + j]) & M32 for j in range(8)])
                self.mem[i : i + 8] = s
        self.next_page()

    @staticmethod
    def _mix(s):
        a, b, c, d, e, f, g, h = s
        a ^= (b << 11) & M32
        d = (d + a) & M32
        b = (b + c) & M32
        b ^= c >> 2
        e = (e + b) & M32
        c = (c + d) & M32
        c ^= (d << 8) & M32
        f = (f + c) & M32
        d = (d + e) & M32
        d ^= e >> 16
        g = (g + d) & M32
        e = (e + f) & M32
        e ^= (f << 10) & M32
        h = (h + e) & M32
        f = (f + g) & M32
        f ^= g >> 4
        a = (a + f) & M32
        g = (g + h) & M32
        g ^= (h << 8) & M32
        b = (b + g) & M32
        h = (h + a) & M32
        h ^= a >> 9
        c = (c + h) & M32
        a = (a + b) & M32
        return [a, b, c, d, e, f, g, h]

    def next_page(self):
        self.c = (self.c + 1) & M32
        self.b = (self.b + self.c) & M32
        for i in range(256):
            x = self.mem[i]
            shifted = (self.a << 13, self.a >> 6, self.a << 2, self.a >> 16)[i & 3]
            self.a = ((self.a ^ (shifted & M32)) + self.mem[(i + 128) & 255]) & M32
            y = self.mem[i] = (self.mem[(x >> 2) & 255] + self.a + self.b) & M32
            self.b = self.rsl[i] = (self.mem[(y >> 10) & 255] + x) & M32


class Stream:
    "The Auth Keys of one direction of a session, by sequence number."

    def __init__(self, seed, your_disc, key, base):
        record = struct.pack("!II", seed, your_disc) + key
        buf = b""
        counter = 0
        while len(buf) < 1024:
            buf += record + bytes([counter & 0xFF])
            counter += 1
        self.isaac = Isaac(buf[:1024])
        self.seed = seed
        self.base = base
        self.page = 0

    def auth_key(self, seq):
        """None for a sequence number behind the page the stream is on, or
        so far ahead of it that it can only be one that went backwards."""
        index = (seq - self.base) & M32
        if index // 256 > self.page + 64:
            return None
        while index // 256 > self.page:
            self.isaac.next_page()
            self.page += 1
        if index // 256 < self.page:
            return None
        return self.isaac.rsl[index % 256]


def self_test():
    "RFC 9986 Section 10: the inputs of Table 1 give the Auth Keys of Table 2."
    stream = Stream(0x0BFD5EED, 0x4002D15C, b"RFC5880June", 0)
    want = [0x9AF65D83, 0x44355D56, 0x9334074E, 0xB643EF59, 0x74D659F1]
    return [stream.auth_key(i) for i in range(5)] == want


def header(state, flags, mult, length, my_disc, your_disc, tx_us, rx_us):
    return struct.pack(
        "!BBBBIIIII",
        1 << 5,
        (state << 6) | flags | FLAG_AUTH,
        mult,
        length,
        my_disc,
        your_disc,
        tx_us,
        rx_us,
        0,
    )


def md5(data):
    "A provider may only let MD5 through when told it is not for security."
    try:
        return hashlib.md5(data, usedforsecurity=False).digest()
    except TypeError:
        return hashlib.md5(data).digest()


def signed_packet(hdr24, key_id, seq, key):
    "RFC 5880 Section 6.7.3, with the mode byte where it has a reserved one."
    body = bytearray(hdr24) + struct.pack(
        "!BBBBI", AUTH_TYPE, 24, key_id, MODE_SIGNED, seq
    )
    body[3] = 48
    digest = md5(bytes(body) + key.ljust(16, b"\0"))
    return bytes(body) + digest


def isaac_packet(hdr24, key_id, seq, seed, auth_key):
    body = bytearray(hdr24) + struct.pack(
        "!BBBBIII", AUTH_TYPE, 16, key_id, MODE_ISAAC, seq, seed, auth_key
    )
    body[3] = 40
    return bytes(body)


def masked(hdr24):
    "What an ISAAC format packet has to repeat of the last signed one."
    hdr = bytearray(hdr24)
    hdr[1] &= ~(FLAG_POLL | FLAG_FINAL) & 0xFF
    hdr[3] = 0
    return bytes(hdr)


class Peer:
    def __init__(self, args):
        self.args = args
        self.key = args.key.encode()
        self.my_disc = struct.unpack("!I", os.urandom(4))[0] | 1
        self.your_disc = 0
        self.state = DOWN
        self.seq = struct.unpack("!I", os.urandom(4))[0]
        self.remote_mult = 3
        self.remote_tx_us = 1000000
        self.last_rx = time.time()
        self.remote_seq = None
        self.injected = 0
        # What is checked of the packets that arrive.
        self.stats = {
            "reached_up": False,
            "ups": 0,
            "signed_ok": 0,
            "signed_bad": 0,
            "isaac_ok": 0,
            "isaac_bad": 0,
            "isaac_with_poll_or_final": 0,
            "isaac_not_up": 0,
            "isaac_header_changed": 0,
            "seed_changed": 0,
            "sequence_not_next": 0,
            "unauthenticated": 0,
            "wrong_type": 0,
            "wrong_key_id": 0,
            "polls_seen": 0,
            "finals_sent": 0,
            "finals_withheld": 0,
            "sent_signed": 0,
            "sent_isaac": 0,
            "forged": {},
            "first_isaac_after_up": None,
            "dropped_signed_seq": None,
            "isaac_skipped": 0,
            "stream_first_seq": None,
        }
        self.reset_epoch()

    def reset_epoch(self):
        "Everything that only lasts for one time up."
        self.tx_stream = None
        self.rx_stream = None
        self.rx_ref = None
        self.peer_signed_up = False
        self.up_since = None
        self.remote_up_since = None
        self.burst = 0
        self.signed_up_sent = 0
        self.isaac_sent = 0
        self.isaac_skipped = 0
        self.poll_sequences = 0
        self.in_poll = False
        self.last_isaac = None
        self.dropped_last_signed = False

    # -- sending -----------------------------------------------------

    def hdr(self, state=None, flags=0, mult=None):
        return header(
            self.state if state is None else state,
            flags,
            self.args.detect_mult if mult is None else mult,
            0,
            self.my_disc,
            self.your_disc,
            self.args.interval_us,
            self.args.interval_us,
        )

    def wants_isaac(self):
        if self.args.signed_only or self.state != UP or not self.peer_signed_up:
            return False
        if self.burst or self.up_since is None:
            return False
        return time.time() - self.up_since >= self.args.hold

    def next_packet(self, flags=0):
        """The next genuine packet, and whether it is in the ISAAC format.
        Takes the sequence number."""
        self.seq = (self.seq + 1) & M32
        if not flags and self.wants_isaac():
            if self.tx_stream is None:
                self.tx_stream = Stream(
                    struct.unpack("!I", os.urandom(4))[0],
                    self.your_disc,
                    self.key,
                    self.seq,
                )
                self.stats["stream_first_seq"] = self.seq
            return (
                isaac_packet(
                    self.hdr(),
                    self.args.key_id,
                    self.seq,
                    self.tx_stream.seed,
                    self.tx_stream.auth_key(self.seq),
                ),
                True,
            )
        if flags:
            self.burst = self.args.detect_mult
        elif self.burst:
            self.burst -= 1
        if self.tx_stream is not None:
            self.tx_stream.auth_key(self.seq)
        return (
            signed_packet(self.hdr(flags=flags), self.args.key_id, self.seq, self.key),
            False,
        )

    def send(self, packet):
        self.tx.sendto(packet, (self.args.peer, BFD_PORT))

    def forged(self, kind):
        "A packet bfdd has to refuse, made out to the next sequence number."
        seq = (self.seq + 1) & M32
        stream = self.tx_stream
        auth_key = stream.auth_key(seq)
        if kind == "auth-key":
            return isaac_packet(
                self.hdr(), self.args.key_id, seq, stream.seed, auth_key ^ 1
            )
        if kind == "seed":
            return isaac_packet(
                self.hdr(), self.args.key_id, seq, stream.seed ^ 1, auth_key
            )
        if kind == "replay":
            return self.last_isaac
        if kind == "header":
            return isaac_packet(
                self.hdr(mult=self.args.detect_mult + 1),
                self.args.key_id,
                seq,
                stream.seed,
                auth_key,
            )
        if kind == "poll":
            return isaac_packet(
                self.hdr(flags=FLAG_POLL), self.args.key_id, seq, stream.seed, auth_key
            )
        if kind == "init":
            return isaac_packet(
                self.hdr(state=INIT), self.args.key_id, seq, stream.seed, auth_key
            )
        if kind == "isaac-key-id":
            return isaac_packet(
                self.hdr(), self.args.key_id + 1, seq, stream.seed, auth_key
            )
        if kind == "key-id":
            return signed_packet(self.hdr(), self.args.key_id + 1, seq, self.key)
        if kind == "digest":
            packet = bytearray(
                signed_packet(self.hdr(), self.args.key_id, seq, self.key)
            )
            packet[-1] ^= 1
            return bytes(packet)
        raise ValueError(kind)

    def periodic(self):
        args = self.args
        if (
            args.inject
            and self.isaac_sent >= 5
            and self.wants_isaac()
            and self.last_isaac is not None
        ):
            kind = args.inject[self.injected % len(args.inject)]
            self.injected += 1
            self.send(self.forged(kind))
            self.stats["forged"][kind] = self.stats["forged"].get(kind, 0) + 1

        # Lose the last signed packet before the stream starts: where the
        # stream was about to start, one more packet is signed, and never
        # sent.
        if (
            args.drop_last_signed
            and not self.dropped_last_signed
            and self.tx_stream is None
            and self.wants_isaac()
        ):
            self.dropped_last_signed = True
            self.seq = (self.seq + 1) & M32
            self.stats["dropped_signed_seq"] = self.seq
            return

        packet, is_isaac = self.next_packet()
        if is_isaac:
            # Lose the first few of the stream, as a bad link would.
            if self.isaac_skipped < args.skip_first_isaac:
                self.isaac_skipped += 1
                self.stats["isaac_skipped"] += 1
                return
            self.isaac_sent += 1
            self.last_isaac = packet
            self.stats["sent_isaac"] += 1
        else:
            if self.state == UP:
                self.signed_up_sent += 1
            self.stats["sent_signed"] += 1
        self.send(packet)

    # -- receiving ---------------------------------------------------

    def check(self, data):
        "Whether a packet from bfdd is what RFC 9986 says it must be."
        stats = self.stats
        if len(data) < 24 or not data[1] & FLAG_AUTH:
            stats["unauthenticated"] += 1
            return False
        if len(data) < 40 or data[24] != AUTH_TYPE:
            stats["wrong_type"] += 1
            return False

        if data[26] != self.args.key_id:
            stats["wrong_key_id"] += 1
            return False

        state = data[1] >> 6
        mode = data[27]
        seq = struct.unpack("!I", data[28:32])[0]
        if self.remote_seq is not None and seq != (self.remote_seq + 1) & M32:
            stats["sequence_not_next"] += 1
        self.remote_seq = seq

        if mode == MODE_SIGNED:
            if len(data) != 48 or data[3] != 48 or data[25] != 24:
                stats["signed_bad"] += 1
                return False
            want = md5(data[:32] + self.key.ljust(16, b"\0"))
            if data[32:48] != want:
                stats["signed_bad"] += 1
                return False
            stats["signed_ok"] += 1
            if self.rx_stream is not None:
                self.rx_stream.auth_key(seq)
            self.rx_ref = masked(data[:24]) if state == UP else None
            return True

        if mode != MODE_ISAAC or len(data) != 40 or data[3] != 40 or data[25] != 16:
            stats["isaac_bad"] += 1
            return False
        seed, auth_key = struct.unpack("!II", data[32:40])
        if data[1] & (FLAG_POLL | FLAG_FINAL):
            stats["isaac_with_poll_or_final"] += 1
        if state != UP or self.state != UP:
            stats["isaac_not_up"] += 1
        if self.rx_ref != masked(data[:24]):
            stats["isaac_header_changed"] += 1
        if self.rx_stream is None:
            # Nothing is lost on the way here, so the first one seen is
            # the first of the stream.
            self.rx_stream = Stream(seed, self.my_disc, self.key, seq)
            if self.remote_up_since is not None:
                stats["first_isaac_after_up"] = round(
                    time.time() - self.remote_up_since, 2
                )
        if seed != self.rx_stream.seed:
            stats["seed_changed"] += 1
            return False
        if auth_key != self.rx_stream.auth_key(seq):
            stats["isaac_bad"] += 1
            return False
        stats["isaac_ok"] += 1
        return True

    def receive(self, data):
        if not self.check(data):
            return
        self.last_rx = time.time()
        remote_state = data[1] >> 6
        self.remote_mult = data[2]
        self.remote_tx_us = struct.unpack("!I", data[12:16])[0]
        self.your_disc = struct.unpack("!I", data[4:8])[0]

        was = self.state
        if remote_state in (DOWN, ADMIN_DOWN):
            if self.state == UP:
                self.state = DOWN
            elif self.state == DOWN and remote_state == DOWN:
                self.state = INIT
        elif remote_state == INIT:
            if self.state in (DOWN, INIT):
                self.state = UP
        elif self.state == INIT:
            self.state = UP
        if self.state != was:
            self.changed_state(was)

        if self.state == UP and remote_state == UP and data[27] == MODE_SIGNED:
            if not self.peer_signed_up:
                self.remote_up_since = time.time()
            self.peer_signed_up = True
            self.stats["reached_up"] = True

        poll = data[1] & FLAG_POLL
        if poll and not self.in_poll:
            self.poll_sequences += 1
            self.stats["polls_seen"] += 1
        self.in_poll = bool(poll)
        if poll:
            self.answer_poll()

    def changed_state(self, was):
        if self.state == UP:
            self.reset_epoch()
            self.up_since = time.time()
            self.stats["ups"] += 1
        elif was == UP:
            self.reset_epoch()
            self.your_disc = 0
            # A new discriminator for the next time up, as bfdd has too.
            self.my_disc = struct.unpack("!I", os.urandom(4))[0] | 1

    def answer_poll(self):
        args = self.args
        # The Poll that comes with going up is always answered, so that
        # what is left unanswered is a check of the key and nothing else.
        later = self.poll_sequences > 1
        if later and args.withhold_final:
            self.stats["finals_withheld"] += 1
            return
        if later and args.final_isaac and self.tx_stream is not None:
            # In the ISAAC format with the right number, and still not a
            # Final bfdd may take.
            seq = (self.seq + 1) & M32
            self.send(
                isaac_packet(
                    self.hdr(flags=FLAG_FINAL),
                    args.key_id,
                    seq,
                    self.tx_stream.seed,
                    self.tx_stream.auth_key(seq),
                )
            )
            self.stats["finals_withheld"] += 1
            return
        packet, _ = self.next_packet(flags=FLAG_FINAL)
        self.send(packet)
        self.stats["finals_sent"] += 1
        self.stats["sent_signed"] += 1

    # -- the loop ----------------------------------------------------

    def run(self):
        args = self.args
        # BFD is received on 3784 but must be sourced from 49152-65535
        # (RFC 5881), so transmit and receive need separate sockets.
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        self.tx.bind((args.local, BFD_SOURCE_PORT))
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind((args.local, BFD_PORT))

        deadline = time.time() + args.seconds
        next_tx = time.time()
        while time.time() < deadline:
            now = time.time()
            if now >= next_tx:
                self.periodic()
                next_tx += args.interval
                continue
            readable, _, _ = select.select([rx], [], [], next_tx - now)
            if readable:
                data, _ = rx.recvfrom(2048)
                self.receive(data)
            # bfdd gone quiet for the detection time of RFC 5880 Section
            # 6.8.4: its Detect Mult times the slower of what it would
            # send at and what we would take.
            detection = (
                self.remote_mult * max(self.remote_tx_us, args.interval_us) / 1000000.0
            )
            if self.state != DOWN and time.time() - self.last_rx > detection:
                was, self.state = self.state, DOWN
                self.changed_state(was)

        self.stats["final_state"] = STATE_NAME[self.state]
        print(json.dumps(self.stats, sort_keys=True))
        return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--local")
    parser.add_argument("--peer")
    parser.add_argument("--key")
    parser.add_argument("--key-id", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=15.0)
    parser.add_argument("--interval", type=float, default=0.3)
    parser.add_argument("--detect-mult", type=int, default=3)
    # How long Up is signalled in signed packets before the ISAAC format.
    parser.add_argument("--hold", type=float, default=2.0)
    # Stay with signed packets for good.
    parser.add_argument("--signed-only", action="store_true")
    # Once in the ISAAC format, send one of these ahead of every packet,
    # each in its turn: auth-key, seed, replay, header, poll, init,
    # isaac-key-id, key-id, digest.
    parser.add_argument("--inject", type=lambda kinds: kinds.split(","))
    # Leave every Poll after the first unanswered, or answer it in the
    # ISAAC format, which comes to the same.
    parser.add_argument("--withhold-final", action="store_true")
    parser.add_argument("--final-isaac", action="store_true")
    # Losses where the stream starts.
    parser.add_argument("--skip-first-isaac", type=int, default=0)
    parser.add_argument("--drop-last-signed", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print("self test: %s" % ("ok" if ok else "FAILED"))
        return 0 if ok else 1

    args.interval_us = int(args.interval * 1000000)
    return Peer(args).run()


if __name__ == "__main__":
    sys.exit(main())
