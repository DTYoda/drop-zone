// The reliable UDP transport.
//
// Run over a real pair of loopback sockets rather than a simulated one, because the
// parts most likely to be wrong are the ones that only appear against a real
// kernel: partial batches from recvmmsg, the interaction between pacing and the
// retransmission timer, and what happens when a send buffer fills.
//
// Loopback loses nothing on its own, so loss is injected deliberately. That is what
// makes the reorder buffer, the selective acknowledgements and the retransmission
// paths actually run: without it a test would only ever exercise the case where
// every packet arrives in order the first time.

#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

#include "dz/client/reliable_udp.hpp"
#include "dz/crypto.hpp"
#include "dz/error.hpp"
#include "dz/socket.hpp"
#include "harness.hpp"

using namespace dz;
using namespace dz::client;

namespace {

/// A UDP socket bound to a loopback port the kernel chooses.
Fd bound_loopback_socket(Endpoint& address) {
    Fd socket_fd(::socket(AF_INET, SOCK_DGRAM, 0));
    if (!socket_fd.valid()) throw dz::test::Failure("cannot create a UDP socket");

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = 0;

    if (::bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        throw dz::test::Failure("cannot bind a UDP socket");
    }

    address = local_endpoint(socket_fd.get());
    return socket_fd;
}

Key test_key() {
    Key key;
    std::memset(key.data(), 0x5a, key.size());
    return key;
}

/// Bytes with a recognisable pattern, so a misplaced chunk shows up as a mismatch at
/// a specific offset rather than as noise.
std::vector<std::uint8_t> patterned_data(std::size_t length) {
    std::vector<std::uint8_t> data(length);
    for (std::size_t i = 0; i < length; ++i) {
        data[i] = static_cast<std::uint8_t>((i * 31 + (i >> 8) * 7) & 0xff);
    }
    return data;
}

/// Move `payload` from one channel to the other and check it arrives intact.
void transfer_and_compare(ReliableUdpChannel& sender, ReliableUdpChannel& receiver,
                          const std::vector<std::uint8_t>& payload) {
    std::exception_ptr sender_error;

    std::thread writer([&] {
        try {
            sender.write_bytes(payload.data(), payload.size());
            sender.flush();
        } catch (...) {
            sender_error = std::current_exception();
        }
    });

    std::vector<std::uint8_t> received(payload.size());
    try {
        receiver.read_exactly(received.data(), received.size());
    } catch (...) {
        writer.join();
        throw;
    }

    writer.join();
    if (sender_error != nullptr) std::rethrow_exception(sender_error);

    for (std::size_t i = 0; i < payload.size(); ++i) {
        if (received[i] != payload[i]) {
            throw dz::test::Failure("byte " + std::to_string(i) + " differs: got " +
                                    std::to_string(received[i]) + ", expected " +
                                    std::to_string(payload[i]));
        }
    }
}

/// A punched pair of channels over loopback, skipping the punch itself since both
/// addresses are already known.
struct ChannelPair {
    ReliableUdpChannel sender;
    ReliableUdpChannel receiver;
};

std::unique_ptr<ChannelPair> make_pair(UdpTuning tuning = UdpTuning{}) {
    Endpoint sender_address;
    Endpoint receiver_address;
    Fd sender_socket = bound_loopback_socket(sender_address);
    Fd receiver_socket = bound_loopback_socket(receiver_address);

    return std::unique_ptr<ChannelPair>(new ChannelPair{
        ReliableUdpChannel(std::move(sender_socket), receiver_address, tuning),
        ReliableUdpChannel(std::move(receiver_socket), sender_address, tuning)});
}

}  // namespace

DZ_TEST(a_small_payload_crosses_a_clean_path) {
    auto pair = make_pair();
    transfer_and_compare(pair->sender, pair->receiver, patterned_data(100));
}

DZ_TEST(a_payload_larger_than_one_datagram_is_reassembled) {
    // Just over three datagrams, so the last one is a partial and the boundaries do
    // not line up with the payload.
    auto pair = make_pair();
    transfer_and_compare(pair->sender, pair->receiver, patterned_data(kUdpMaxPayload * 3 + 17));
}

DZ_TEST(a_multi_megabyte_payload_crosses_a_clean_path) {
    // Enough packets that the congestion window leaves slow start and the
    // acknowledgement handling runs thousands of times.
    auto pair = make_pair();
    transfer_and_compare(pair->sender, pair->receiver, patterned_data(4 * 1024 * 1024));

    DZ_CHECK(pair->sender.statistics().packets_sent > 3000);
    DZ_CHECK(pair->receiver.statistics().packets_received > 3000);
}

DZ_TEST(several_writes_form_one_stream) {
    // The transport is a byte stream, not a datagram service: what the receiver reads
    // must not depend on how the sender split its writes.
    auto pair = make_pair();

    std::vector<std::uint8_t> payload = patterned_data(300000);
    std::exception_ptr sender_error;

    std::thread writer([&] {
        try {
            std::size_t offset = 0;
            for (std::size_t batch : {1u, 7u, 1000u, 65536u, 100000u}) {
                std::size_t length = std::min(batch, payload.size() - offset);
                pair->sender.write_bytes(payload.data() + offset, length);
                offset += length;
            }
            pair->sender.write_bytes(payload.data() + offset, payload.size() - offset);
            pair->sender.flush();
        } catch (...) {
            sender_error = std::current_exception();
        }
    });

    // Read back in completely different sized pieces.
    std::vector<std::uint8_t> received(payload.size());
    std::size_t offset = 0;
    for (std::size_t batch : {3u, 999u, 50000u}) {
        std::size_t length = std::min(batch, received.size() - offset);
        pair->receiver.read_exactly(received.data() + offset, length);
        offset += length;
    }
    pair->receiver.read_exactly(received.data() + offset, received.size() - offset);

    writer.join();
    if (sender_error != nullptr) std::rethrow_exception(sender_error);
    DZ_CHECK(received == payload);
}

DZ_TEST(data_survives_two_percent_packet_loss) {
    // Two per cent is severe for a real path and makes retransmission and the reorder
    // buffer run constantly. Nothing may be lost, duplicated or delivered out of
    // order to the caller.
    auto pair = make_pair();
    pair->sender.set_test_loss_rate(0.02);

    transfer_and_compare(pair->sender, pair->receiver, patterned_data(2 * 1024 * 1024));

    const UdpStatistics& stats = pair->sender.statistics();
    DZ_CHECK(stats.packets_retransmitted > 0);
    // A retransmitted packet arrives after the ones that followed it, so the receiver
    // must have had to hold early arrivals while a gap filled -- which is exactly the
    // reorder buffer doing its job.
    DZ_CHECK(pair->receiver.statistics().reordered_received > 0);
}

DZ_TEST(data_survives_loss_in_both_directions) {
    // Losing acknowledgements is a different failure from losing data: the sender
    // retransmits packets that did in fact arrive, and the receiver has to recognise
    // and discard the duplicates.
    auto pair = make_pair();
    pair->sender.set_test_loss_rate(0.02);
    pair->receiver.set_test_loss_rate(0.05);

    transfer_and_compare(pair->sender, pair->receiver, patterned_data(1024 * 1024));
    DZ_CHECK(pair->receiver.statistics().duplicates_received > 0);
}

DZ_TEST(data_survives_ten_percent_packet_loss) {
    // Well past the point where TCP would collapse. Slow, but it must still finish
    // and still be correct.
    UdpTuning tuning;
    tuning.max_timeouts = 40;

    auto pair = make_pair(tuning);
    pair->sender.set_test_loss_rate(0.10);

    transfer_and_compare(pair->sender, pair->receiver, patterned_data(512 * 1024));
}

DZ_TEST(the_stream_works_in_both_directions_at_once) {
    // The receiver sends the transfer acknowledgement back over the same channel, so
    // the reverse direction has to be a working stream and not just a path for
    // acknowledgements.
    auto pair = make_pair();

    std::vector<std::uint8_t> forward = patterned_data(200000);
    std::vector<std::uint8_t> backward = patterned_data(150000);

    std::atomic<bool> ok{true};

    std::thread peer([&] {
        try {
            std::vector<std::uint8_t> got(forward.size());
            pair->receiver.read_exactly(got.data(), got.size());
            if (got != forward) ok = false;

            pair->receiver.write_bytes(backward.data(), backward.size());
            pair->receiver.flush();
        } catch (...) {
            ok = false;
        }
    });

    pair->sender.write_bytes(forward.data(), forward.size());
    pair->sender.flush();

    std::vector<std::uint8_t> got(backward.size());
    pair->sender.read_exactly(got.data(), got.size());

    peer.join();
    DZ_CHECK(ok.load());
    DZ_CHECK(got == backward);
}

DZ_TEST(the_round_trip_time_estimate_is_populated) {
    auto pair = make_pair();
    transfer_and_compare(pair->sender, pair->receiver, patterned_data(1024 * 1024));

    // Loopback is fast but not instantaneous, and an estimator that never produced a
    // sample would leave the retransmission timer at its initial value forever.
    DZ_CHECK(pair->sender.statistics().smoothed_rtt_us > 0);
}

DZ_TEST(a_silent_peer_is_eventually_given_up_on) {
    // A path that stops working must fail rather than hang, so a transfer to a
    // machine that has been unplugged does not wait indefinitely.
    Endpoint sender_address;
    Fd sender_socket = bound_loopback_socket(sender_address);

    // A port nothing is listening on. Its own address with the port changed, so it is
    // routable but unanswered.
    Endpoint nowhere = sender_address;
    nowhere.set_port(static_cast<std::uint16_t>(sender_address.port() ^ 0x4000));

    UdpTuning tuning;
    tuning.max_timeouts = 3;
    tuning.initial_rto_us = 20'000;
    tuning.max_rto_us = 50'000;

    ReliableUdpChannel channel(std::move(sender_socket), nowhere, tuning);

    std::vector<std::uint8_t> payload(10000, 0xab);
    auto send_into_the_void = [&] {
        channel.write_bytes(payload.data(), payload.size());
        channel.flush();
    };
    DZ_CHECK_THROWS(send_into_the_void());
}

DZ_TEST(hole_punching_agrees_on_a_path) {
    Endpoint left_address;
    Endpoint right_address;
    Fd left = bound_loopback_socket(left_address);
    Fd right = bound_loopback_socket(right_address);

    Key key = test_key();

    // Both peers probe at once, which is the whole idea: each side's outbound probe
    // is what teaches its own NAT to accept the other's.
    Endpoint left_found;
    Endpoint right_found;
    std::atomic<bool> left_ok{false};
    std::atomic<bool> right_ok{false};

    std::thread left_thread([&] {
        left_ok = punch_udp_path(left.get(), {right_address}, key, /*is_sender=*/true, 3000,
                                 left_found);
    });
    right_ok = punch_udp_path(right.get(), {left_address}, key, /*is_sender=*/false, 3000,
                              right_found);
    left_thread.join();

    DZ_CHECK(left_ok.load());
    DZ_CHECK(right_ok.load());
    DZ_CHECK_EQUAL(left_found.port(), right_address.port());
    DZ_CHECK_EQUAL(right_found.port(), left_address.port());
}

DZ_TEST(hole_punching_ignores_a_peer_with_the_wrong_key) {
    // Without an authenticated probe, anything that happened to send a datagram to
    // the punching socket would be adopted as the peer.
    Endpoint left_address;
    Endpoint right_address;
    Fd left = bound_loopback_socket(left_address);
    Fd right = bound_loopback_socket(right_address);

    Key right_key;
    std::memset(right_key.data(), 0x11, right_key.size());

    Endpoint found;
    std::atomic<bool> right_ok{false};

    std::thread right_thread([&] {
        Endpoint theirs;
        right_ok = punch_udp_path(right.get(), {left_address}, right_key, /*is_sender=*/false, 1200,
                                  theirs);
    });

    bool left_ok = punch_udp_path(left.get(), {right_address}, test_key(), /*is_sender=*/true, 1200,
                                  found);
    right_thread.join();

    DZ_CHECK(!left_ok);
    DZ_CHECK(!right_ok.load());
}

DZ_TEST(hole_punching_gives_up_on_an_unreachable_candidate) {
    Endpoint address;
    Fd socket_fd = bound_loopback_socket(address);

    Endpoint nowhere = address;
    nowhere.set_port(static_cast<std::uint16_t>(address.port() ^ 0x4000));

    Endpoint found;
    DZ_CHECK(!punch_udp_path(socket_fd.get(), {nowhere}, test_key(), true, 600, found));
}
