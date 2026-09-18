// Framing and payload parsing.
//
// The point of most of these is not that a well-formed message round-trips, but
// that a malformed one is rejected rather than read past the end of the buffer. The
// C prototype parsed messages with strtok over a fixed 1 KiB buffer and had no way
// to tell a truncated message from a complete one, so this is the layer where that
// class of bug had to be designed out.

#include "dz/frame.hpp"
#include "dz/protocol.hpp"
#include "dz/socket.hpp"
#include "harness.hpp"

using namespace dz;

DZ_TEST(frame_header_round_trip) {
    FrameHeader header;
    header.type = MessageType::Chunk;
    header.flags = 0xbeef;
    header.length = 1234567;

    std::uint8_t bytes[kFrameHeaderSize];
    encode_frame_header(header, bytes);

    FrameHeader decoded = decode_frame_header(bytes);
    DZ_CHECK_EQUAL(decoded.version, kProtocolVersion);
    DZ_CHECK(decoded.type == MessageType::Chunk);
    DZ_CHECK_EQUAL(decoded.flags, 0xbeef);
    DZ_CHECK_EQUAL(decoded.length, 1234567u);
}

DZ_TEST(frame_header_rejects_a_future_version) {
    std::uint8_t bytes[kFrameHeaderSize] = {};
    bytes[0] = kProtocolVersion + 1;
    DZ_CHECK_THROWS(decode_frame_header(bytes));
}

DZ_TEST(frame_header_rejects_an_oversized_length) {
    FrameHeader header;
    header.length = kMaxFrameLength;

    std::uint8_t bytes[kFrameHeaderSize];
    encode_frame_header(header, bytes);
    // At the limit exactly is fine.
    DZ_CHECK_EQUAL(decode_frame_header(bytes).length, kMaxFrameLength);

    // One byte over must be refused, because the length is about to size an
    // allocation.
    header.length = kMaxFrameLength + 1;
    encode_frame_header(header, bytes);
    DZ_CHECK_THROWS(decode_frame_header(bytes));
}

DZ_TEST(payload_round_trips_every_field_type) {
    PayloadWriter writer;
    writer.put_u8(0x7f);
    writer.put_u16(0xabcd);
    writer.put_u32(0xdeadbeef);
    writer.put_u64(0x0123456789abcdefull);
    writer.put_bool(true);
    writer.put_string("drop-zone");

    std::uint8_t blob[] = {1, 2, 3, 4, 5};
    writer.put_bytes(blob, sizeof(blob));

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);

    DZ_CHECK_EQUAL(reader.take_u8(), 0x7f);
    DZ_CHECK_EQUAL(reader.take_u16(), 0xabcd);
    DZ_CHECK_EQUAL(reader.take_u32(), 0xdeadbeefu);
    DZ_CHECK_EQUAL(reader.take_u64(), 0x0123456789abcdefull);
    DZ_CHECK_EQUAL(reader.take_bool(), true);
    DZ_CHECK_EQUAL(reader.take_string(), std::string("drop-zone"));
    DZ_CHECK_EQUAL(reader.take_bytes().size(), sizeof(blob));
    DZ_CHECK(reader.empty());
}

DZ_TEST(payload_reader_refuses_to_read_past_the_end) {
    PayloadWriter writer;
    writer.put_u32(42);

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);

    DZ_CHECK_EQUAL(reader.take_u32(), 42u);
    DZ_CHECK_THROWS(reader.take_u8());
}

DZ_TEST(payload_reader_refuses_a_length_that_overruns_the_frame) {
    // A blob claiming a hundred bytes in a frame that holds four. Reading it would
    // walk off the end of the buffer, which is precisely the bug this check exists
    // to prevent.
    PayloadWriter writer;
    writer.put_u32(100);
    writer.put_u32(0);

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);
    DZ_CHECK_THROWS(reader.take_bytes());
}

DZ_TEST(payload_reader_refuses_an_impossible_endpoint_count) {
    // Sixty thousand endpoints declared in an eight-byte frame. Rejected before any
    // allocation, so a forged count cannot be turned into a memory-exhaustion
    // attack.
    PayloadWriter writer;
    writer.put_u16(60000);
    writer.put_u32(0);

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);
    DZ_CHECK_THROWS(reader.take_endpoints());
}

DZ_TEST(take_fixed_requires_the_exact_length) {
    PayloadWriter writer;
    std::uint8_t blob[8] = {};
    writer.put_bytes(blob, sizeof(blob));

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);

    std::uint8_t out[16];
    DZ_CHECK_THROWS(reader.take_fixed(out, 16));
}

DZ_TEST(endpoints_round_trip_through_a_payload) {
    Endpoint v4;
    DZ_CHECK(Endpoint::parse("192.168.1.50:47654", v4));

    Endpoint v6;
    DZ_CHECK(Endpoint::parse("[2001:db8::1]:9000", v6));

    PayloadWriter writer;
    writer.put_endpoints({v4, v6});

    std::vector<std::uint8_t> bytes = writer.take();
    PayloadReader reader(bytes);

    std::vector<Endpoint> decoded = reader.take_endpoints();
    DZ_CHECK_EQUAL(decoded.size(), 2u);
    DZ_CHECK_EQUAL(decoded[0].to_string(), std::string("192.168.1.50:47654"));
    DZ_CHECK_EQUAL(decoded[1].to_string(), std::string("[2001:db8::1]:9000"));
}

DZ_TEST(endpoint_parsing_rejects_malformed_input) {
    Endpoint endpoint;
    DZ_CHECK(!Endpoint::parse("", endpoint));
    DZ_CHECK(!Endpoint::parse("192.168.1.1", endpoint));         // No port.
    DZ_CHECK(!Endpoint::parse("192.168.1.1:0", endpoint));       // Port zero.
    DZ_CHECK(!Endpoint::parse("192.168.1.1:70000", endpoint));   // Out of range.
    DZ_CHECK(!Endpoint::parse("192.168.1.1:abc", endpoint));     // Not a number.
    DZ_CHECK(!Endpoint::parse("2001:db8::1", endpoint));         // Unbracketed IPv6.
    DZ_CHECK(!Endpoint::parse("not-a-host:80", endpoint));       // Not a literal.
}

DZ_TEST(a_v4_mapped_address_is_unwrapped_on_arrival) {
    // A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d. Left in that
    // form it would be handed to the other peer as a candidate only an IPv6 socket
    // could reach.
    sockaddr_in6 raw{};
    raw.sin6_family = AF_INET6;
    raw.sin6_port = htons(1234);
    raw.sin6_addr.s6_addr[10] = 0xff;
    raw.sin6_addr.s6_addr[11] = 0xff;
    raw.sin6_addr.s6_addr[12] = 10;
    raw.sin6_addr.s6_addr[13] = 0;
    raw.sin6_addr.s6_addr[14] = 0;
    raw.sin6_addr.s6_addr[15] = 7;

    Endpoint endpoint =
        Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&raw), sizeof(raw));

    DZ_CHECK_EQUAL(endpoint.family(), AF_INET);
    DZ_CHECK_EQUAL(endpoint.to_string(), std::string("10.0.0.7:1234"));

    // And back again, for sending from a dual-stack socket.
    Endpoint mapped = endpoint.as_v4_mapped();
    DZ_CHECK_EQUAL(mapped.family(), AF_INET6);
    DZ_CHECK_EQUAL(mapped.port(), 1234);
}

DZ_TEST(endpoint_adaptation_matches_a_sockets_family) {
    Endpoint v4;
    DZ_CHECK(Endpoint::parse("10.1.2.3:500", v4));

    Endpoint adapted;
    DZ_CHECK(adapt_endpoint_for_socket(v4, AF_INET, adapted));
    DZ_CHECK_EQUAL(adapted.family(), AF_INET);

    DZ_CHECK(adapt_endpoint_for_socket(v4, AF_INET6, adapted));
    DZ_CHECK_EQUAL(adapted.family(), AF_INET6);

    Endpoint v6;
    DZ_CHECK(Endpoint::parse("[2001:db8::5]:500", v6));
    // A real IPv6 address cannot be reached from an IPv4 socket at all.
    DZ_CHECK(!adapt_endpoint_for_socket(v6, AF_INET, adapted));
}

DZ_TEST(chunk_headers_round_trip) {
    ChunkHeader header;
    header.file_index = 7;
    header.plaintext_length = kDefaultChunkSize;
    header.offset = 42ull * 1024 * 1024 * 1024;  // Past 4 GiB, so the u64 matters.
    header.counter = 1234567890123ull;

    std::uint8_t bytes[kChunkHeaderSize];
    encode_chunk_header(header, bytes);

    ChunkHeader decoded = decode_chunk_header(bytes);
    DZ_CHECK_EQUAL(decoded.file_index, 7u);
    DZ_CHECK_EQUAL(decoded.plaintext_length, kDefaultChunkSize);
    DZ_CHECK_EQUAL(decoded.offset, header.offset);
    DZ_CHECK_EQUAL(decoded.counter, header.counter);
}

DZ_TEST(a_personal_send_request_round_trips_without_a_group_field) {
    SendRequest request;
    request.target_username = "bob";
    request.transport_hint = TransportKind::DirectTcp;
    for (std::size_t i = 0; i < kSha256Size; ++i) request.proof[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0; i < kEd25519SignatureSize; ++i) {
        request.signature[i] = static_cast<std::uint8_t>(0xff - i);
    }

    SendRequest decoded = SendRequest::decode(request.encode());
    DZ_CHECK_EQUAL(decoded.target_username, std::string("bob"));
    DZ_CHECK(decoded.group_name.empty());
    DZ_CHECK(decoded.transport_hint == TransportKind::DirectTcp);
    DZ_CHECK_EQUAL(decoded.proof[3], 3);
}

DZ_TEST(a_group_send_request_carries_the_group_name) {
    SendRequest request;
    request.target_username = "bob";
    request.group_name = "friends";
    request.transport_hint = TransportKind::None;
    for (std::size_t i = 0; i < kSha256Size; ++i) request.proof[i] = 1;
    for (std::size_t i = 0; i < kEd25519SignatureSize; ++i) request.signature[i] = 2;

    SendRequest decoded = SendRequest::decode(request.encode());
    DZ_CHECK_EQUAL(decoded.target_username, std::string("bob"));
    DZ_CHECK_EQUAL(decoded.group_name, std::string("friends"));

    PeerIntroduction intro;
    intro.username = "alice";
    intro.group_name = "friends";
    intro.pairing_id = 99;
    intro.transport_hint = TransportKind::HolePunchUdp;

    PeerIntroduction decoded_intro = PeerIntroduction::decode(intro.encode());
    DZ_CHECK_EQUAL(decoded_intro.username, std::string("alice"));
    DZ_CHECK_EQUAL(decoded_intro.group_name, std::string("friends"));
    DZ_CHECK_EQUAL(decoded_intro.pairing_id, 99u);
}

DZ_TEST(group_control_messages_round_trip) {
    GroupQuery query;
    query.name = "friends";
    DZ_CHECK_EQUAL(GroupQuery::decode(query.encode()).name, std::string("friends"));

    GroupStatus status;
    status.exists = true;
    status.member_count = 3;
    GroupStatus decoded_status = GroupStatus::decode(status.encode());
    DZ_CHECK(decoded_status.exists);
    DZ_CHECK_EQUAL(decoded_status.member_count, 3u);

    GroupJoin join;
    join.name = "friends";
    for (std::size_t i = 0; i < kSha256Size; ++i) join.verifier[i] = static_cast<std::uint8_t>(i);
    GroupJoin decoded_join = GroupJoin::decode(join.encode());
    DZ_CHECK_EQUAL(decoded_join.name, std::string("friends"));
    DZ_CHECK_EQUAL(decoded_join.verifier[7], 7);

    GroupResult result;
    result.outcome = GroupJoinOutcome::Created;
    result.message = "created group friends";
    result.member_count = 1;
    GroupResult decoded_result = GroupResult::decode(result.encode());
    DZ_CHECK(decoded_result.outcome == GroupJoinOutcome::Created);
    DZ_CHECK_EQUAL(decoded_result.message, std::string("created group friends"));
    DZ_CHECK_EQUAL(decoded_result.member_count, 1u);

    GroupRoster roster;
    roster.usernames = {"alice", "bob"};
    GroupRoster decoded_roster = GroupRoster::decode(roster.encode());
    DZ_CHECK_EQUAL(decoded_roster.usernames.size(), 2u);
    DZ_CHECK_EQUAL(decoded_roster.usernames[1], std::string("bob"));
}

DZ_TEST(control_messages_round_trip) {
    ClientHello hello;
    hello.role = ClientRole::Receiver;
    hello.username = "alice";
    hello.tcp_port = 47001;
    hello.udp_port = 47001;
    for (std::size_t i = 0; i < kEd25519PublicKeySize; ++i) {
        hello.identity_key[i] = static_cast<std::uint8_t>(i);
    }
    for (std::size_t i = 0; i < kX25519KeySize; ++i) {
        hello.session_key[i] = static_cast<std::uint8_t>(0xff - i);
    }

    Endpoint candidate;
    DZ_CHECK(Endpoint::parse("192.168.0.4:47001", candidate));
    hello.local_candidates.push_back(candidate);

    ClientHello decoded = ClientHello::decode(hello.encode());
    DZ_CHECK(decoded.role == ClientRole::Receiver);
    DZ_CHECK_EQUAL(decoded.username, std::string("alice"));
    DZ_CHECK_EQUAL(decoded.tcp_port, 47001);
    DZ_CHECK_EQUAL(decoded.local_candidates.size(), 1u);
    DZ_CHECK_EQUAL(decoded.identity_key[5], 5);
    DZ_CHECK_EQUAL(decoded.session_key[5], 0xff - 5);
}

DZ_TEST(a_hello_with_an_invalid_username_is_rejected) {
    ClientHello hello;
    hello.username = "Alice; rm -rf /";

    // Encoding is permissive -- it is the decode side that faces the network -- so
    // the check has to be there.
    DZ_CHECK_THROWS(ClientHello::decode(hello.encode()));
}

DZ_TEST(an_offer_whose_total_disagrees_with_its_files_is_rejected) {
    TransferOffer offer;
    offer.sender_username = "alice";
    offer.display_name = "stuff";
    offer.chunk_size = kDefaultChunkSize;

    ManifestEntry entry;
    entry.path = "a.bin";
    entry.size = 100;
    offer.entries.push_back(entry);

    // Claiming a total that does not match the sum would let a sender make the
    // receiver reserve far more space than it is going to fill.
    offer.total_bytes = 999999;

    std::vector<std::uint8_t> encoded = offer.encode();
    DZ_CHECK_THROWS(TransferOffer::decode(encoded.data(), encoded.size()));
}

DZ_TEST(an_offer_with_a_zero_chunk_size_is_rejected) {
    TransferOffer offer;
    offer.sender_username = "alice";
    offer.chunk_size = 0;

    std::vector<std::uint8_t> encoded = offer.encode();
    DZ_CHECK_THROWS(TransferOffer::decode(encoded.data(), encoded.size()));
}

DZ_TEST(an_offer_cannot_ask_for_setuid_files) {
    TransferOffer offer;
    offer.sender_username = "alice";
    offer.chunk_size = kDefaultChunkSize;

    ManifestEntry entry;
    entry.path = "trojan";
    entry.size = 0;
    entry.mode = 04755;  // setuid
    offer.entries.push_back(entry);
    offer.total_bytes = 0;

    std::vector<std::uint8_t> encoded = offer.encode();
    TransferOffer decoded = TransferOffer::decode(encoded.data(), encoded.size());

    // Masked down to permission bits, so a peer cannot have a setuid binary created.
    DZ_CHECK_EQUAL(decoded.entries[0].mode, 0755u);
}

DZ_TEST(reflexive_probe_replies_round_trip) {
    Endpoint observed;
    DZ_CHECK(Endpoint::parse("203.0.113.9:51234", observed));

    std::uint8_t reply[kMaxReflexiveReplySize];
    std::size_t length = encode_reflexive_reply(observed, reply, sizeof(reply));

    Endpoint decoded;
    DZ_CHECK(decode_reflexive_reply(reply, length, decoded));
    DZ_CHECK_EQUAL(decoded.to_string(), std::string("203.0.113.9:51234"));

    // Anything that is not a reply is reported as such rather than throwing: it
    // arrived over UDP from anywhere at all.
    std::uint8_t junk[] = {'x', 'y', 'z', 'w', 1, 2, 3};
    DZ_CHECK(!decode_reflexive_reply(junk, sizeof(junk), decoded));
}

DZ_TEST(transport_names_parse_and_print) {
    TransportKind kind;
    DZ_CHECK(parse_transport_kind("tcp", kind));
    DZ_CHECK(kind == TransportKind::DirectTcp);
    DZ_CHECK(parse_transport_kind("udp", kind));
    DZ_CHECK(kind == TransportKind::HolePunchUdp);
    DZ_CHECK(parse_transport_kind("relay", kind));
    DZ_CHECK(kind == TransportKind::ServerRelay);
    DZ_CHECK(parse_transport_kind("auto", kind));
    DZ_CHECK(kind == TransportKind::None);
    DZ_CHECK(!parse_transport_kind("carrier-pigeon", kind));
}
