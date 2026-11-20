#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_auth_isaac_topo1.py
# Part of NetDEF Topology Tests
#

"""
test_bfd_auth_isaac_topo1.py: the optimized MD5 meticulous keyed ISAAC
authentication of RFC 9986, with the procedures of RFC 9985.

        +---------+                        +---------+
        |         | eth-rt1        eth-rt2 |         |
        |   RT2   +------------------------+   RT1   |
        | 10.0.1.2|           s1           |10.0.1.1 |
        +---------+                        |         |
                                           |         |
        +---------+                        |         |
        |         | eth-rt1        eth-rt3 |         |
        |   RT3   +------------------------+         |
        | 10.0.2.3|           s2           |10.0.2.1 |
        +---------+                        +---------+

RT1 and RT2 run bfdd with the option, and show what it does to a session
as it is configured, reconfigured and has its keys changed.

RT3 runs no BFD. It is the namespace a scripted peer speaks from, which
has its own MD5 and its own ISAAC. Two routers running the same code can
agree with each other and both be wrong, so that peer checks every packet
bfdd sends against RFC 9986, and sends bfdd the packets no implementation
would, to see them refused.
"""

import json
import os
import shlex
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

KEY = "isaacauthkey01"
OTHER_KEY = "anotherkey0001"

RT1_RT2 = "10.0.1.1"
RT2_ADDR = "10.0.1.2"
RT1_RT3 = "10.0.2.1"
RT3_ADDR = "10.0.2.3"
RT3_IFACE = "eth-rt1"

# How rt1 and rt2 name their session with each other, and rt1 its session
# with the scripted peer.
PEER = {
    "rt1": "peer {} local-address {} interface eth-rt2".format(RT2_ADDR, RT1_RT2),
    "rt2": "peer {} local-address {} interface eth-rt1".format(RT1_RT2, RT2_ADDR),
}
PEER_RT3 = "peer {} local-address {} interface eth-rt3".format(RT3_ADDR, RT1_RT3)

TYPE_NAME = "optimized md5 meticulous keyed-isaac"

# What the scripted peer counts when bfdd sends something it should not.
PEER_COMPLAINTS = (
    "signed_bad",
    "isaac_bad",
    "isaac_with_poll_or_final",
    "isaac_not_up",
    "isaac_header_changed",
    "seed_changed",
    "sequence_not_next",
    "unauthenticated",
    "wrong_type",
    "wrong_key_id",
)

# The packets the scripted peer can forge, and the counter each is refused
# under.
FORGED = {
    "auth-key": "rxOptimizedAuthKeyMismatch",
    "seed": "rxOptimizedSeedChanged",
    "replay": "rxOptimizedSequenceError",
    "header": "rxOptimizedNotSigned",
    "poll": "rxOptimizedNotSigned",
    "init": "rxOptimizedNotSigned",
    "isaac-key-id": "rxOptimizedKeyId",
    "key-id": "rxOptimizedKeyId",
    "digest": "rxOptimizedDigestMismatch",
}


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt2", "rt2:eth-rt1"),
        "s2": ("rt1:eth-rt3", "rt3:eth-rt1"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    get_topogen().stop_topology()


MD5_REFUSED = "the crypto library refuses MD5"


def skip_on_failure():
    """Nothing here can run where MD5 is not to be had.

    A build that uses OpenSSL may be run with a provider that refuses it,
    and the sessions then stay down, as they should.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    for rname, peer in (("rt1", RT2_ADDR), ("rt2", RT1_RT2)):
        if auth(rname, peer).get("optimizedUnused") == MD5_REFUSED:
            pytest.skip("{}: {}".format(rname, MD5_REFUSED))


def session(rname, peer):
    "What `rname` shows for its session with `peer`."
    router = get_topogen().gears[rname]
    for info in json.loads(router.vtysh_cmd("show bfd peers json")):
        if info.get("peer") == peer:
            return info
    return {}


def counters(rname, peer):
    router = get_topogen().gears[rname]
    for info in json.loads(router.vtysh_cmd("show bfd peers counters json")):
        if info.get("peer") == peer:
            return info
    return {}


def auth(rname, peer):
    return session(rname, peer).get("authentication", {})


def configure(rname, *lines):
    logger.info("%s: %s", rname, "; ".join(lines))
    get_topogen().gears[rname].vtysh_cmd(
        "configure terminal\n{}\n".format("\n".join(lines))
    )


def configure_peer(rname, *lines):
    "Configure the session rt1 and rt2 have with each other."
    configure(rname, "bfd", PEER[rname], *lines)


def expect(func, what, count=40, wait=0.5):
    _, result = topotest.run_and_expect(func, True, count=count, wait=wait)
    assert result is True, what


def expect_status(rname, peer, want, count=40):
    expect(
        lambda: session(rname, peer).get("status") == want,
        "{} session with {} did not go {}, it is {}".format(
            rname, peer, want, session(rname, peer).get("status")
        ),
        count=count,
    )


def expect_both(want, count=40):
    expect_status("rt1", RT2_ADDR, want, count=count)
    expect_status("rt2", RT1_RT2, want, count=count)


def formats(rname, peer):
    info = auth(rname, peer)
    return info.get("optimizedTransmitFormat"), info.get("optimizedReceiveFormat")


def expect_isaac_both_ways():
    "Both ends have left the signed packets for the ISAAC format."
    for rname, peer in (("rt1", RT2_ADDR), ("rt2", RT1_RT2)):
        expect(
            lambda: formats(rname, peer) == ("isaac", "isaac"),
            "{} is not sending and receiving the ISAAC format: {}".format(
                rname, formats(rname, peer)
            ),
        )


def test_isaac_session_comes_up():
    "Two routers with the option bring the session up and stop signing."
    skip_on_failure()

    expect_both("up")
    expect_isaac_both_ways()

    for rname, peer in (("rt1", RT2_ADDR), ("rt2", RT1_RT2)):
        info = auth(rname, peer)
        assert info.get("enabled") is True
        assert info.get("optimized") is True
        assert info.get("cryptoName") == TYPE_NAME
        assert info.get("reauthInterval") == 60
        assert "optimizedUnused" not in info

    # With nothing to authenticate again for, nothing more is signed,
    # once a Poll Sequence that was under way has run its course.
    for rname in ("rt1", "rt2"):
        configure_peer(rname, "authentication reauth-interval 0")
    time.sleep(2)
    expect_isaac_both_ways()
    before = counters("rt1", RT2_ADDR)
    expect(
        lambda: counters("rt1", RT2_ADDR)["optimizedIsaacPacketInput"]
        > before["optimizedIsaacPacketInput"] + 5,
        "rt1 is not counting ISAAC format packets",
    )
    after = counters("rt1", RT2_ADDR)
    for rname in ("rt1", "rt2"):
        configure_peer(rname, "no authentication reauth-interval")
    assert after["optimizedSignedPacketOutput"] == before["optimizedSignedPacketOutput"]
    assert after["optimizedSignedPacketInput"] == before["optimizedSignedPacketInput"]
    assert after.get("rx-pkt-authentication-failure", 0) == 0


def test_isaac_configuration_is_shown():
    "The running configuration has what was configured, and no more."
    skip_on_failure()

    expect_both("up")
    config = get_topogen().gears["rt1"].vtysh_cmd("show running-config")
    assert "  authentication optimized\n" in config
    assert "reauth-interval" not in config

    configure_peer("rt1", "authentication reauth-interval 0")
    config = get_topogen().gears["rt1"].vtysh_cmd("show running-config")
    assert "  authentication reauth-interval 0\n" in config
    assert auth("rt1", RT2_ADDR).get("reauthInterval") == 0

    configure_peer("rt1", "no authentication reauth-interval")
    config = get_topogen().gears["rt1"].vtysh_cmd("show running-config")
    assert "reauth-interval" not in config
    assert auth("rt1", RT2_ADDR).get("reauthInterval") == 60
    assert session("rt1", RT2_ADDR).get("status") == "up"


def test_isaac_session_is_authenticated_again():
    """With an interval, the session signs a Poll and gets a signed Final.

    The session stays up through it, and with the interval back at its
    default nothing more is signed.
    """
    skip_on_failure()

    expect_isaac_both_ways()
    before = counters("rt1", RT2_ADDR)

    configure_peer("rt1", "authentication reauth-interval 2")
    # A Poll and the packets that follow it, several times over.
    expect(
        lambda: counters("rt1", RT2_ADDR)["optimizedSignedPacketOutput"]
        > before["optimizedSignedPacketOutput"] + 12,
        "rt1 is not signing Polls every interval",
    )
    configure_peer("rt1", "no authentication reauth-interval")

    after = counters("rt1", RT2_ADDR)
    assert after["session-up"] == before["session-up"], "the session went down"
    assert after.get("reauthFailures", 0) == 0
    assert after.get("rx-pkt-authentication-failure", 0) == 0
    expect_isaac_both_ways()


def test_isaac_key_change_takes_the_session_down():
    """A session keeps the keys it came up with, and goes down without them.

    RFC 9986 Section 11.2. With different keys on the two ends it stays
    down, and with the new key on both it comes back.
    """
    skip_on_failure()

    expect_both("up")
    lost = counters("rt1", RT2_ADDR).get("sessionKeysLost", 0)
    configure("rt1", "key chain kc1", "key 1", "key-string {}".format(OTHER_KEY))
    expect_status("rt1", RT2_ADDR, "down")
    assert counters("rt1", RT2_ADDR).get("sessionKeysLost", 0) == lost + 1
    expect_status("rt2", RT1_RT2, "down")

    # Long enough to come up, had the keys matched.
    time.sleep(5)
    assert session("rt1", RT2_ADDR).get("status") == "down"
    assert session("rt2", RT1_RT2).get("status") != "up"

    configure("rt2", "key chain kc1", "key 1", "key-string {}".format(OTHER_KEY))
    expect_both("up")

    for rname in ("rt1", "rt2"):
        configure(rname, "key chain kc1", "key 1", "key-string {}".format(KEY))
    expect_both("up", count=60)
    expect_isaac_both_ways()


def test_isaac_option_on_one_side_only():
    """A session does not come up with a peer that has not got the option.

    rt2 is given a cleartext key to go on with, so that it has something
    to send: rt1 has to refuse that, not merely hear nothing.
    """
    skip_on_failure()

    expect_both("up")
    expect_isaac_both_ways()
    configure_peer("rt2", "no authentication optimized")
    configure(
        "rt2",
        "key chain kc1",
        "key 2",
        "key-string plainpassword",
        "cryptographic-algorithm cleartext",
    )
    expect_both("down")
    assert "optimized" not in auth("rt2", RT1_RT2)
    assert auth("rt2", RT1_RT2).get("cryptoName") == "simple-password"
    # What rt2 counted while it had the option is still there to see.
    assert counters("rt2", RT1_RT2)["optimizedIsaacPacketInput"] > 0

    sent = counters("rt2", RT1_RT2)["control-packet-output"]
    refused = counters("rt1", RT2_ADDR).get("rxOptimizedMalformed", 0)
    expect(
        lambda: counters("rt2", RT1_RT2)["control-packet-output"] > sent + 3
        and counters("rt1", RT2_ADDR).get("rxOptimizedMalformed", 0) > refused + 3,
        "rt2 is not sending, or rt1 is not refusing what it sends",
    )
    assert session("rt1", RT2_ADDR).get("status") == "down"
    assert session("rt2", RT1_RT2).get("status") == "down"

    configure("rt2", "key chain kc1", "no key 2")
    configure_peer("rt2", "authentication optimized")
    expect_both("up")


@pytest.mark.parametrize(
    "command,undo,reason",
    [
        (
            "detect-multiplier 86",
            "detect-multiplier 3",
            "the detect multiplier is above 85",
        ),
        ("demand-mode", "no demand-mode", "it is not available with demand mode"),
    ],
)
def test_isaac_not_available(command, undo, reason):
    "What the option cannot be used with keeps the session down, and says so."
    skip_on_failure()

    expect_both("up")
    configure_peer("rt1", command)
    expect_status("rt1", RT2_ADDR, "down")
    info = auth("rt1", RT2_ADDR)
    assert info.get("enabled") is False
    assert info.get("optimizedUnused") == reason
    text = get_topogen().gears["rt1"].vtysh_cmd("show bfd peers")
    assert "Optimized authentication: not in use, {}".format(reason) in text

    time.sleep(3)
    assert session("rt1", RT2_ADDR).get("status") == "down"

    configure_peer("rt1", undo)
    expect_both("up")


def test_isaac_key_too_short():
    "RFC 9986 Section 8 wants a key of 8 bytes at least."
    skip_on_failure()

    expect_both("up")
    for rname in ("rt1", "rt2"):
        configure(rname, "key chain kc1", "key 1", "key-string sevenby")
    expect_both("down")
    assert auth("rt1", RT2_ADDR).get("optimizedUnused") == (
        "the key-chain has no md5 key to send with "
        "(8 to 16 bytes, ID up to 255, in its send lifetime)"
    )

    for rname in ("rt1", "rt2"):
        configure(rname, "key chain kc1", "key 1", "key-string {}".format(KEY))
    expect_both("up")


def test_isaac_through_a_profile():
    "The option and the interval can come from a profile, the peer's own first."
    skip_on_failure()

    for rname in ("rt1", "rt2"):
        configure(
            rname,
            "bfd",
            "profile isaac",
            "authentication key-chain kc1",
            "authentication optimized",
            "authentication reauth-interval 30",
        )
        configure_peer(
            rname,
            "no authentication optimized",
            "no authentication key-chain kc1",
            "profile isaac",
        )
    expect_both("up")
    expect_isaac_both_ways()
    assert auth("rt1", RT2_ADDR).get("reauthInterval") == 30

    configure_peer("rt1", "authentication reauth-interval 0")
    assert auth("rt1", RT2_ADDR).get("reauthInterval") == 0
    assert auth("rt2", RT1_RT2).get("reauthInterval") == 30
    configure_peer("rt1", "no authentication reauth-interval")
    assert auth("rt1", RT2_ADDR).get("reauthInterval") == 30
    assert session("rt1", RT2_ADDR).get("status") == "up"


#
# The scripted peer.
#


def address_in_kernel(router, ifname, address):
    "True once `address` is on `ifname`: zebra installs it after it starts."
    output = router.run("ip -4 -j addr show dev {}".format(ifname))
    try:
        interfaces = json.loads(output)
    except ValueError:
        return False
    if not interfaces:
        return False
    return any(
        info.get("local") == address for info in interfaces[0].get("addr_info", [])
    )


def peer_command(*options):
    return [
        sys.executable,
        os.path.join(CWD, "bfd_isaac_peer.py"),
        "--local",
        RT3_ADDR,
        "--peer",
        RT1_RT3,
        "--key",
        KEY,
    ] + list(options)


def run_peer(*options):
    """Speak BFD from rt3 until the peer is done.

    Returns what the peer saw, and rt1's counters for the session from
    before the peer started and after it was done. The session an earlier
    run left behind has gone down by then, so that is not in them.

    rt1 forgets the sequence number of an earlier run after twice the
    detection time, which a session that is down has at three seconds.
    Waiting for that keeps the new one from being refused at first, and
    counted.
    """
    rt3 = get_topogen().gears["rt3"]
    expect(
        lambda: address_in_kernel(rt3, RT3_IFACE, RT3_ADDR),
        "{} is not on {}".format(RT3_ADDR, RT3_IFACE),
    )
    expect_status("rt1", RT3_ADDR, "down")
    time.sleep(8)

    command = shlex.join(peer_command(*options))
    logger.info("running scripted peer: %s", command)
    before = counters("rt1", RT3_ADDR)
    output = rt3.run(command)
    after = counters("rt1", RT3_ADDR)
    logger.info("scripted peer: %s", output)
    return json.loads(output.strip().splitlines()[-1]), before, after


def assert_peer_content(stats):
    "bfdd sent nothing the scripted peer found fault with."
    for name in PEER_COMPLAINTS:
        assert stats[name] == 0, "the scripted peer counted {}: {}".format(name, stats)


def test_peer_generator_is_the_rfcs():
    "The scripted peer's ISAAC gives the Auth Keys of RFC 9986 Section 10."
    skip_on_failure()

    output = get_topogen().gears["rt3"].run(shlex.join(peer_command("--self-test")))
    assert "self test: ok" in output, output


def test_peer_finds_bfdd_conforming():
    """Every packet bfdd sends is what RFC 9986 says it must be.

    The digests and the Auth Keys check out against the peer's own MD5 and
    ISAAC, the sequence number goes up by one each time, a Poll or a Final
    is never in the ISAAC format, and an ISAAC format packet only repeats
    the header last signed. bfdd in turn refuses nothing the peer sends.
    """
    skip_on_failure()

    stats, before, after = run_peer("--seconds", "15")

    assert stats["reached_up"] and stats["final_state"] == "Up", stats
    assert stats["ups"] == 1, "the session went down under the peer: {}".format(stats)
    assert_peer_content(stats)
    assert stats["signed_ok"] > 5 and stats["isaac_ok"] > 10, stats
    # RFC 9985: Up is signalled in signed packets for a detection time
    # first. That is the one in force when the first of them goes out,
    # before the timers are negotiated: three times a second.
    assert stats["first_isaac_after_up"] >= 2.9, stats

    assert after.get("rx-pkt-authentication-failure", 0) == before.get(
        "rx-pkt-authentication-failure", 0
    )
    assert (
        after["optimizedIsaacPacketInput"] - before["optimizedIsaacPacketInput"]
        == stats["sent_isaac"]
    )
    assert (
        after["optimizedIsaacPacketOutput"] - before["optimizedIsaacPacketOutput"]
        >= stats["isaac_ok"]
    )


def test_peer_forged_packets_are_refused():
    """bfdd refuses what does not check out, and the session is none the worse.

    Ahead of each of its packets the peer sends one made out to the same
    sequence number that is wrong in one way: the Auth Key, the Seed, an
    old sequence number, a header that is not the one last signed, a Poll
    or a state other than Up in the ISAAC format, another key, a bad
    digest. Had bfdd taken any, it would have refused the real packet that
    followed, and the session would have gone down.
    """
    skip_on_failure()

    stats, before, after = run_peer("--seconds", "25", "--inject", ",".join(FORGED))

    assert stats["ups"] == 1 and stats["final_state"] == "Up", stats
    assert_peer_content(stats)
    assert set(stats["forged"]) == set(FORGED), stats

    want = {}
    for kind, name in FORGED.items():
        want[name] = want.get(name, 0) + stats["forged"][kind]
    for name, count in want.items():
        assert (
            after.get(name, 0) - before.get(name, 0) == count
        ), "{}: {} forged, {} counted".format(
            name, count, after.get(name, 0) - before.get(name, 0)
        )
    assert after.get("rx-pkt-authentication-failure", 0) - before.get(
        "rx-pkt-authentication-failure", 0
    ) == sum(want.values())


@pytest.mark.parametrize("answer", ["--withhold-final", "--final-isaac"])
def test_peer_without_a_signed_final_is_dropped(answer):
    """A peer that does not answer a Poll with a signed Final is not kept.

    RFC 9985 Section 5. The peer goes on sending ISAAC format packets that
    check out, and either leaves the Poll unanswered or answers it in the
    ISAAC format with the right Auth Key. Neither shows it still has the
    key, and bfdd takes the session down.
    """
    skip_on_failure()

    configure("rt1", "bfd", PEER_RT3, "authentication reauth-interval 3")
    stats, before, after = run_peer("--seconds", "15", answer)
    configure("rt1", "bfd", PEER_RT3, "no authentication reauth-interval")

    assert stats["reached_up"] and stats["finals_withheld"] > 0, stats
    assert_peer_content(stats)
    assert after.get("reauthFailures", 0) > before.get("reauthFailures", 0)
    assert after["session-down"] > before["session-down"]
    if answer == "--final-isaac":
        assert after.get("rxOptimizedNotSigned", 0) > before.get(
            "rxOptimizedNotSigned", 0
        )


def test_peer_that_only_signs():
    "Each end decides for itself: bfdd uses the ISAAC format, the peer never."
    skip_on_failure()

    stats, before, after = run_peer("--seconds", "12", "--signed-only")

    assert stats["ups"] == 1 and stats["final_state"] == "Up", stats
    assert_peer_content(stats)
    assert stats["isaac_ok"] > 5 and stats["sent_isaac"] == 0, stats
    assert after["optimizedIsaacPacketInput"] == before["optimizedIsaacPacketInput"]
    assert after["optimizedIsaacPacketOutput"] > before["optimizedIsaacPacketOutput"]


def test_peer_losses_where_the_stream_starts():
    """bfdd finds the peer's stream though packets were lost as it began.

    The last signed packet before it and the first two of the stream never
    arrive. RFC 9986 Section 10.2 read to the letter puts the stream one
    place off after that, and every packet of it is refused until the
    session times out.
    """
    skip_on_failure()

    stats, before, after = run_peer(
        "--seconds",
        "14",
        "--detect-mult",
        "5",
        "--drop-last-signed",
        "--skip-first-isaac",
        "2",
    )

    assert stats["ups"] == 1 and stats["final_state"] == "Up", stats
    assert_peer_content(stats)
    # The losses were where they were meant to be: a signed packet, and
    # then the two that the stream starts with.
    assert stats["dropped_signed_seq"] is not None, stats
    assert (
        stats["stream_first_seq"] == (stats["dropped_signed_seq"] + 1) & 0xFFFFFFFF
    ), stats
    assert stats["isaac_skipped"] == 2, stats
    assert stats["sent_isaac"] > 5, stats
    assert (
        after["optimizedIsaacPacketInput"] - before["optimizedIsaacPacketInput"]
        == stats["sent_isaac"]
    )
    assert after.get("rx-pkt-authentication-failure", 0) == before.get(
        "rx-pkt-authentication-failure", 0
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
