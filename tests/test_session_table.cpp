// Ephemeral groups in the server's session table: create, join, wrong password,
// and vanishing when the last member's socket goes away.

#include <cstring>
#include <memory>

#include "dz/crypto.hpp"
#include "dz/protocol.hpp"
#include "dz/server/connection.hpp"
#include "dz/server/session_table.hpp"
#include "dz/socket.hpp"
#include "harness.hpp"

using namespace dz;
using namespace dz::server;

namespace {

ConnectionPtr make_receiver(const std::string& username, std::uint64_t id) {
    ConnectionPtr connection = std::make_shared<Connection>(Fd(), id, 0);
    connection->state = ConnectionState::ReceiverIdle;
    connection->claimed_username = username;
    connection->hello.username = username;
    connection->hello_received = true;
    return connection;
}

void fill_verifier(std::uint8_t out[kSha256Size], std::uint8_t value) {
    std::memset(out, value, kSha256Size);
}

}  // namespace

DZ_TEST(a_group_is_created_by_the_first_joiner) {
    SessionTable table;
    ConnectionPtr alice = make_receiver("alice", 1);

    std::uint8_t verifier[kSha256Size];
    fill_verifier(verifier, 0xaa);

    DZ_CHECK(!table.group_exists("friends"));
    DZ_CHECK(table.join_group("friends", verifier, alice) == GroupJoinResult::Created);
    DZ_CHECK(table.group_exists("friends"));
    DZ_CHECK_EQUAL(table.group_member_count("friends"), 1u);
}

DZ_TEST(a_second_joiner_must_present_the_same_verifier) {
    SessionTable table;
    ConnectionPtr alice = make_receiver("alice", 1);
    ConnectionPtr bob = make_receiver("bob", 2);

    std::uint8_t verifier[kSha256Size];
    fill_verifier(verifier, 0xaa);
    std::uint8_t wrong[kSha256Size];
    fill_verifier(wrong, 0xbb);

    DZ_CHECK(table.join_group("friends", verifier, alice) == GroupJoinResult::Created);
    DZ_CHECK(table.join_group("friends", wrong, bob) == GroupJoinResult::WrongPassword);
    DZ_CHECK_EQUAL(table.group_member_count("friends"), 1u);

    DZ_CHECK(table.join_group("friends", verifier, bob) == GroupJoinResult::Joined);
    DZ_CHECK_EQUAL(table.group_member_count("friends"), 2u);
}

DZ_TEST(leaving_destroys_an_empty_group) {
    SessionTable table;
    ConnectionPtr alice = make_receiver("alice", 1);
    ConnectionPtr bob = make_receiver("bob", 2);

    std::uint8_t verifier[kSha256Size];
    fill_verifier(verifier, 0x11);

    table.join_group("friends", verifier, alice);
    table.join_group("friends", verifier, bob);
    table.leave_group("friends", alice.get());
    DZ_CHECK(table.group_exists("friends"));
    DZ_CHECK_EQUAL(table.group_member_count("friends"), 1u);

    table.leave_group("friends", bob.get());
    DZ_CHECK(!table.group_exists("friends"));
    DZ_CHECK_EQUAL(table.group_member_count("friends"), 0u);
}

DZ_TEST(a_dropped_connection_is_no_longer_in_the_group) {
    SessionTable table;
    std::uint8_t verifier[kSha256Size];
    fill_verifier(verifier, 0x22);

    {
        ConnectionPtr alice = make_receiver("alice", 1);
        DZ_CHECK(table.join_group("friends", verifier, alice) == GroupJoinResult::Created);
        DZ_CHECK(table.group_exists("friends"));
    }

    // alice's socket is gone, so the group is gone. The next joiner is first.
    DZ_CHECK(!table.group_exists("friends"));

    ConnectionPtr bob = make_receiver("bob", 2);
    std::uint8_t other[kSha256Size];
    fill_verifier(other, 0x33);
    DZ_CHECK(table.join_group("friends", other, bob) == GroupJoinResult::Created);
}

DZ_TEST(idle_group_members_skip_busy_peers_and_the_sender) {
    SessionTable table;
    ConnectionPtr alice = make_receiver("alice", 1);
    ConnectionPtr bob = make_receiver("bob", 2);
    ConnectionPtr carol = make_receiver("carol", 3);

    std::uint8_t verifier[kSha256Size];
    fill_verifier(verifier, 0x44);
    table.join_group("friends", verifier, alice);
    table.join_group("friends", verifier, bob);
    table.join_group("friends", verifier, carol);

    bob->state = ConnectionState::ReceiverMatched;

    std::vector<ConnectionPtr> idle = table.idle_group_members("friends", "carol");
    DZ_CHECK_EQUAL(idle.size(), 1u);
    DZ_CHECK_EQUAL(idle[0]->claimed_username, std::string("alice"));
}
