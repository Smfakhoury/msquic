/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for the QUIC_ACK_TRACKER module.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "AckTrackerTest.cpp.clog.h"
#endif

//
// Helper to create a minimal valid context for testing ack tracker functions
// that require a QUIC_PACKET_SPACE and QUIC_CONNECTION. Uses real structs to
// ensure proper memory layout when QuicAckTrackerGetPacketSpace() does
// CXPLAT_CONTAINING_RECORD pointer arithmetic.
//
struct AckTrackerTestContext {
    QUIC_CONNECTION Connection;
    QUIC_PACKET_SPACE PacketSpace;

    AckTrackerTestContext() {
        CxPlatZeroMemory(&Connection, sizeof(Connection));
        CxPlatZeroMemory(&PacketSpace, sizeof(PacketSpace));
        PacketSpace.Connection = &Connection;
        //
        // Mark Send as uninitialized so QuicSendValidate (debug builds)
        // returns early without dereferencing uninitialized connection state.
        //
        Connection.Send.Uninitialized = TRUE;
        QuicAckTrackerInitialize(&PacketSpace.AckTracker);
    }

    ~AckTrackerTestContext() {
        QuicAckTrackerUninitialize(&PacketSpace.AckTracker);
    }

    QUIC_ACK_TRACKER* Tracker() { return &PacketSpace.AckTracker; }
};

//
// Test: Initialize and Uninitialize lifecycle.
// Scenario: Verifies QuicAckTrackerInitialize sets up both internal ranges
// and QuicAckTrackerUninitialize cleans them up. After initialization, the
// tracker should have empty ranges, no packets to ack, and default state.
// Assertions: Both ranges have zero size, HasPacketsToAck returns FALSE.
//
TEST(AckTrackerTest, InitializeUninitialize)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));

    QuicAckTrackerInitialize(&Tracker);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: Reset clears all tracker state.
// Scenario: Populates the tracker with packets and non-default state, then
// calls QuicAckTrackerReset. Verifies all counters, flags, ECN data, and
// ranges are restored to initial values.
// Assertions: All fields zeroed, both ranges empty, HasPacketsToAck FALSE.
//
TEST(AckTrackerTest, ResetClearsState)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));

    QuicAckTrackerInitialize(&Tracker);

    //
    // Populate state before reset.
    //
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersReceived, 10);
    Tracker.AckElicitingPacketsToAcknowledge = 5;
    Tracker.LargestPacketNumberAcknowledged = 100;
    Tracker.LargestPacketNumberRecvTime = 999;
    Tracker.AlreadyWrittenAckFrame = TRUE;
    Tracker.NonZeroRecvECN = TRUE;
    Tracker.ReceivedECN.ECT_0_Count = 3;
    Tracker.ReceivedECN.ECT_1_Count = 2;
    Tracker.ReceivedECN.CE_Count = 1;

    QuicAckTrackerReset(&Tracker);

    ASSERT_EQ(Tracker.AckElicitingPacketsToAcknowledge, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberAcknowledged, 0u);
    ASSERT_EQ(Tracker.LargestPacketNumberRecvTime, 0u);
    ASSERT_FALSE(Tracker.AlreadyWrittenAckFrame);
    ASSERT_FALSE(Tracker.NonZeroRecvECN);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.ECT_1_Count, 0u);
    ASSERT_EQ(Tracker.ReceivedECN.CE_Count, 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 0u);
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 0u);
    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber returns FALSE for non-duplicate packets.
// Scenario: Adds a new packet number for the first time. The function should
// return FALSE since the packet is not a duplicate.
// Assertions: Return value is FALSE.
//
TEST(AckTrackerTest, AddPacketNumberNotDuplicate)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 42));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber returns TRUE for duplicate packets.
// Scenario: Adds the same packet number twice. The second add should return
// TRUE indicating a duplicate was detected.
// Assertions: First add returns FALSE, second add returns TRUE.
//
TEST(AckTrackerTest, AddPacketNumberDuplicate)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 42));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 42));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber with multiple sequential packet numbers.
// Scenario: Adds a sequence of distinct packet numbers. None should be
// detected as duplicates. The received range should contain all of them.
// Assertions: All adds return FALSE, range size reflects merged contiguous range.
//
TEST(AckTrackerTest, AddPacketNumberMultipleSequential)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    for (uint64_t i = 0; i < 10; i++) {
        ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, i));
    }

    //
    // Contiguous range [0..9] should merge into a single sub-range.
    //
    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 1u);

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AddPacketNumber with non-contiguous packet numbers.
// Scenario: Adds packet numbers with gaps to create multiple sub-ranges in
// the received set. Verifies duplicate detection works across ranges.
// Assertions: Two sub-ranges exist, duplicates detected for both ranges.
//
TEST(AckTrackerTest, AddPacketNumberNonContiguous)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 10));
    ASSERT_FALSE(QuicAckTrackerAddPacketNumber(&Tracker, 20));

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersReceived), 2u);

    //
    // Duplicates in each sub-range should be detected.
    //
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 10));
    ASSERT_TRUE(QuicAckTrackerAddPacketNumber(&Tracker, 20));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: HasPacketsToAck returns FALSE on empty tracker.
// Scenario: An initialized tracker with no packets added should have no
// packets to acknowledge.
// Assertions: HasPacketsToAck returns FALSE.
//
TEST(AckTrackerTest, HasPacketsToAckEmpty)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: HasPacketsToAck returns TRUE when packets exist and frame not written.
// Scenario: Adds a packet to the ack range and verifies HasPacketsToAck
// returns TRUE when AlreadyWrittenAckFrame is FALSE.
// Assertions: HasPacketsToAck returns TRUE after adding a packet.
//
TEST(AckTrackerTest, HasPacketsToAckWithPackets)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    Tracker.AlreadyWrittenAckFrame = FALSE;

    ASSERT_TRUE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: HasPacketsToAck returns FALSE when ACK frame already written.
// Scenario: Adds a packet to the ack range but sets AlreadyWrittenAckFrame
// to TRUE. HasPacketsToAck should return FALSE since the frame was already sent.
// Assertions: HasPacketsToAck returns FALSE despite non-empty range.
//
TEST(AckTrackerTest, HasPacketsToAckAlreadyWritten)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    Tracker.AlreadyWrittenAckFrame = TRUE;

    ASSERT_FALSE(QuicAckTrackerHasPacketsToAck(&Tracker));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE when threshold is zero.
// Scenario: With ReorderingThreshold=0, the reordering check is disabled
// regardless of the ack range state.
// Assertions: Returns FALSE.
//
TEST(AckTrackerTest, ReorderingThresholdZeroReturnsFalse)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 20);

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 0));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE with fewer than 2 sub-ranges.
// Scenario: A single contiguous range has no gaps, so the reordering
// threshold cannot be hit.
// Assertions: Returns FALSE with a single sub-range.
//
TEST(AckTrackerTest, ReorderingThresholdSingleRangeReturnsFalse)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 11);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 1u);
    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 1));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns TRUE when gap exceeds threshold.
// Scenario: Creates two sub-ranges [0] and [5] with a gap of 4 packets
// (1,2,3,4). With LargestPacketNumberAcknowledged=0, LargestReported=
// SmallestTracked=0. The smallest missing packet after range [0] is 1.
// LargestUnacked(5) - PreviousSmallestMissing(1) = 4 >= threshold(2) → TRUE.
// Assertions: Returns TRUE.
//
TEST(AckTrackerTest, ReorderingThresholdExceeded)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE when gap is below threshold.
// Scenario: Creates two sub-ranges [0] and [3] with a gap of 2 (1,2).
// LargestUnacked(3) - PreviousSmallestMissing(1) = 2. With threshold=3,
// 2 < 3, so the threshold is not hit.
// Assertions: Returns FALSE.
//
TEST(AckTrackerTest, ReorderingThresholdNotExceeded)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 3);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold returns FALSE when LargestReported >= RangeStart.
// Scenario: Creates two sub-ranges [10] and [15]. Sets LargestPacketNumberAcknowledged
// high enough that LargestReported (Acked - Threshold + 1) >= the start of the
// highest range. The loop should find LargestReported >= RangeStart and return FALSE.
// Assertions: Returns FALSE.
//
TEST(AckTrackerTest, ReorderingThresholdLargestReportedBeyondRange)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 15);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    //
    // Set LargestPacketNumberAcknowledged = 20 with threshold = 2.
    // LargestReported = 20 - 2 + 1 = 19 >= RangeStart(15) → return FALSE.
    //
    Tracker.LargestPacketNumberAcknowledged = 20;

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with multiple ranges checks all gaps.
// Scenario: Creates three sub-ranges [0], [5], [10]. The loop iterates from
// the highest range downward, checking gaps. With threshold=3, the gap between
// range [0..0] and [5..5] (missing 1-4, smallest=1) gives
// LargestUnacked(10) - PreviousSmallestMissing(1) = 9 >= 3 → TRUE.
// Assertions: Returns TRUE after examining multiple ranges.
//
TEST(AckTrackerTest, ReorderingThresholdMultipleRanges)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 3u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with LargestReported adjusting PreviousSmallestMissing.
// Scenario: Creates ranges [0,1] and [5]. LargestPacketNumberAcknowledged = 3 with
// threshold = 2. LargestReported = 3 - 2 + 1 = 2. PreviousSmallestMissing =
// QuicRangeGetHigh([0,1]) + 1 = 2. LargestReported(2) > PreviousSmallestMissing(2)
// is FALSE, so PreviousSmallestMissing stays 2. LargestUnacked(5) - 2 = 3 >= 2 → TRUE.
// Assertions: Returns TRUE.
//
TEST(AckTrackerTest, ReorderingThresholdAdjustedSmallestMissing)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 1);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 3;

    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with LargestReported > PreviousSmallestMissing.
// Scenario: Creates ranges [0] and [4,5] and [10]. LargestPacketNumberAcknowledged = 8
// with threshold = 2. LargestReported = 8 - 2 + 1 = 7. When checking the gap before
// range [4,5], PreviousSmallestMissing = high([0]) + 1 = 1. Since LargestReported(7) >
// PreviousSmallestMissing(1), it adjusts to 7. LargestUnacked(10) - 7 = 3 >= 2 → TRUE.
// Assertions: Returns TRUE with adjusted PreviousSmallestMissing.
//
TEST(AckTrackerTest, ReorderingThresholdLargestReportedAdjustsMissing)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 4);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 5);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 3u);

    Tracker.LargestPacketNumberAcknowledged = 8;

    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold loop exhausts all ranges without hitting threshold.
// Scenario: Creates ranges [0] and [2] with a gap of only 1 packet. With threshold=3,
// LargestUnacked(2) - PreviousSmallestMissing(1) = 1 < 3 → FALSE. The loop exits
// after checking all ranges without finding a sufficient gap.
// Assertions: Returns FALSE after iterating all ranges.
//
TEST(AckTrackerTest, ReorderingThresholdLoopExhausted)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 0);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 2);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 0;

    ASSERT_FALSE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 3));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: DidHitReorderingThreshold with LargestReported falling to SmallestTracked.
// Scenario: LargestPacketNumberAcknowledged is smaller than SmallestTracked +
// ReorderingThreshold, so LargestReported = SmallestTracked. Creates ranges
// [10] and [15]. LargestPacketNumberAcknowledged = 10, threshold = 2.
// Since 10 < 10 + 2 = 12, LargestReported = SmallestTracked = 10.
// PreviousSmallestMissing = high([10]) + 1 = 11.
// LargestReported(10) > PreviousSmallestMissing(11) is FALSE.
// LargestUnacked(15) - 11 = 4 >= 2 → TRUE.
// Assertions: Returns TRUE with LargestReported clamped to SmallestTracked.
//
TEST(AckTrackerTest, ReorderingThresholdLargestReportedClampedToSmallest)
{
    QUIC_ACK_TRACKER Tracker;
    CxPlatZeroMemory(&Tracker, sizeof(Tracker));
    QuicAckTrackerInitialize(&Tracker);

    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 10);
    QuicRangeAddValue(&Tracker.PacketNumbersToAck, 15);

    ASSERT_EQ(QuicRangeSize(&Tracker.PacketNumbersToAck), 2u);

    Tracker.LargestPacketNumberAcknowledged = 10;

    ASSERT_TRUE(QuicAckTrackerDidHitReorderingThreshold(&Tracker, 2));

    QuicAckTrackerUninitialize(&Tracker);
}

//
// Test: AckPacket with NON_ACK_ELICITING type adds to ack range without
// incrementing AckElicitingPacketsToAcknowledge.
// Scenario: Calls QuicAckTrackerAckPacket with QUIC_ACK_TYPE_NON_ACK_ELICITING.
// The packet should be added to PacketNumbersToAck, ECN should be handled, but
// AckElicitingPacketsToAcknowledge should remain zero.
// Assertions: PacketNumbersToAck contains packet, AckElicitingPacketsToAcknowledge=0,
// AlreadyWrittenAckFrame=FALSE, LargestPacketNumberRecvTime updated.
//
TEST(AckTrackerTest, AckPacketNonAckEliciting)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        5,          // PacketNumber
        1000,       // RecvTimeUs
        CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 1u);
    ASSERT_EQ(QuicRangeGetMax(&Ctx.Tracker()->PacketNumbersToAck), 5u);
    ASSERT_EQ(Ctx.Tracker()->AckElicitingPacketsToAcknowledge, 0u);
    ASSERT_FALSE(Ctx.Tracker()->AlreadyWrittenAckFrame);
    ASSERT_EQ(Ctx.Tracker()->LargestPacketNumberRecvTime, 1000u);
}

//
// Test: AckPacket detects out-of-order packets.
// Scenario: First adds packet 10, then adds packet 5 which is out of order
// (smaller than current largest). The connection's ReorderedPackets counter
// should be incremented.
// Assertions: ReorderedPackets incremented to 1 after out-of-order packet.
//
TEST(AckTrackerTest, AckPacketOutOfOrder)
{
    AckTrackerTestContext Ctx;

    //
    // First packet establishes the largest.
    //
    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        10,
        1000,
        CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_EQ(Ctx.Connection.Stats.Recv.ReorderedPackets, 0u);

    //
    // Second packet is out of order (5 < 10).
    //
    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        5,
        2000,
        CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_EQ(Ctx.Connection.Stats.Recv.ReorderedPackets, 1u);

    //
    // Verify both packets are in the ack range.
    //
    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 2u);
}

//
// Test: AckPacket correctly tracks ECN ECT_1 type.
// Scenario: Calls AckPacket with CXPLAT_ECN_ECT_1. Verifies ECT_1_Count is
// incremented and NonZeroRecvECN flag is set.
// Assertions: ECT_1_Count=1, NonZeroRecvECN=TRUE, other ECN counts=0.
//
TEST(AckTrackerTest, AckPacketEcnEct1)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        1,
        1000,
        CXPLAT_ECN_ECT_1,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(Ctx.Tracker()->NonZeroRecvECN);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_1_Count, 1u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.CE_Count, 0u);
}

//
// Test: AckPacket correctly tracks ECN ECT_0 type.
// Scenario: Calls AckPacket with CXPLAT_ECN_ECT_0. Verifies ECT_0_Count is
// incremented and NonZeroRecvECN flag is set.
// Assertions: ECT_0_Count=1, NonZeroRecvECN=TRUE, other ECN counts=0.
//
TEST(AckTrackerTest, AckPacketEcnEct0)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        1,
        1000,
        CXPLAT_ECN_ECT_0,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(Ctx.Tracker()->NonZeroRecvECN);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_0_Count, 1u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_1_Count, 0u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.CE_Count, 0u);
}

//
// Test: AckPacket correctly tracks ECN CE (Congestion Experienced) type.
// Scenario: Calls AckPacket with CXPLAT_ECN_CE. Verifies CE_Count is
// incremented and NonZeroRecvECN flag is set.
// Assertions: CE_Count=1, NonZeroRecvECN=TRUE, other ECN counts=0.
//
TEST(AckTrackerTest, AckPacketEcnCE)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        1,
        1000,
        CXPLAT_ECN_CE,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(Ctx.Tracker()->NonZeroRecvECN);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.CE_Count, 1u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_0_Count, 0u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_1_Count, 0u);
}

//
// Test: AckPacket with multiple ECN types accumulates counts correctly.
// Scenario: Sends multiple packets with different ECN types. Verifies all
// counters accumulate independently.
// Assertions: Each ECN counter reflects the number of packets with that type.
//
TEST(AckTrackerTest, AckPacketEcnMultipleTypes)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 1, 1000, CXPLAT_ECN_ECT_0,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 2, 2000, CXPLAT_ECN_ECT_1,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 3, 3000, CXPLAT_ECN_CE,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 4, 4000, CXPLAT_ECN_ECT_0,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_TRUE(Ctx.Tracker()->NonZeroRecvECN);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_0_Count, 2u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.ECT_1_Count, 1u);
    ASSERT_EQ(Ctx.Tracker()->ReceivedECN.CE_Count, 1u);
}

//
// Test: AckPacket with ACK_ELICITING type increments counter and takes
// early exit when ACK is already queued.
// Scenario: Pre-sets QUIC_CONN_SEND_FLAG_ACK in SendFlags, then calls
// AckPacket with ACK_ELICITING. The function should increment the counter
// but take the early exit since ACK is already queued.
// Assertions: AckElicitingPacketsToAcknowledge incremented, packet in range.
//
TEST(AckTrackerTest, AckPacketAckElicitingAlreadyQueued)
{
    AckTrackerTestContext Ctx;

    //
    // Pre-set the ACK flag so the function takes the early exit path.
    //
    Ctx.Connection.Send.SendFlags |= QUIC_CONN_SEND_FLAG_ACK;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        7,
        5000,
        CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_ACK_ELICITING);

    ASSERT_EQ(Ctx.Tracker()->AckElicitingPacketsToAcknowledge, 1u);
    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 1u);
    ASSERT_EQ(QuicRangeGetMax(&Ctx.Tracker()->PacketNumbersToAck), 7u);
    ASSERT_FALSE(Ctx.Tracker()->AlreadyWrittenAckFrame);
}

//
// Test: AckPacket clears AlreadyWrittenAckFrame on new packet.
// Scenario: Sets AlreadyWrittenAckFrame to TRUE, then calls AckPacket.
// The function should clear the flag since new unacknowledged data arrived.
// Assertions: AlreadyWrittenAckFrame is FALSE after AckPacket.
//
TEST(AckTrackerTest, AckPacketClearsAlreadyWrittenFlag)
{
    AckTrackerTestContext Ctx;

    Ctx.Tracker()->AlreadyWrittenAckFrame = TRUE;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(),
        1,
        1000,
        CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);

    ASSERT_FALSE(Ctx.Tracker()->AlreadyWrittenAckFrame);
}

//
// Test: AckPacket updates LargestPacketNumberRecvTime for new largest packet.
// Scenario: Sends packet 10 then packet 20. The recv time should be updated
// to the time of packet 20 (the new largest). Then sends packet 15 (not the
// largest), recv time should remain at packet 20's time.
// Assertions: LargestPacketNumberRecvTime tracks the largest packet's time.
//
TEST(AckTrackerTest, AckPacketUpdatesRecvTimeForLargest)
{
    AckTrackerTestContext Ctx;

    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 10, 1000, CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Ctx.Tracker()->LargestPacketNumberRecvTime, 1000u);

    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 20, 2000, CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Ctx.Tracker()->LargestPacketNumberRecvTime, 2000u);

    //
    // Packet 15 is not the new largest, so recv time should not change.
    //
    QuicAckTrackerAckPacket(
        Ctx.Tracker(), 15, 3000, CXPLAT_ECN_NON_ECT,
        QUIC_ACK_TYPE_NON_ACK_ELICITING);
    ASSERT_EQ(Ctx.Tracker()->LargestPacketNumberRecvTime, 2000u);
}

//
// Test: OnAckFrameAcked removes packet numbers up to the acked largest.
// Scenario: Adds packets 0-4 to the ack range, then calls OnAckFrameAcked
// with LargestAckedPacketNumber=2. All packets <= 2 should be removed, leaving
// only packets 3 and 4 in the range.
// Assertions: Range contains only [3,4] after the call.
//
TEST(AckTrackerTest, OnAckFrameAckedRemovesRange)
{
    AckTrackerTestContext Ctx;

    //
    // Add packets 0 through 4.
    //
    for (uint64_t i = 0; i <= 4; i++) {
        QuicRangeAddValue(&Ctx.Tracker()->PacketNumbersToAck, i);
    }
    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 1u);

    QuicAckTrackerOnAckFrameAcked(Ctx.Tracker(), 2);

    //
    // Packets 0, 1, 2 removed. Remaining: [3, 4].
    //
    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 1u);
    ASSERT_EQ(QuicRangeGetMin(&Ctx.Tracker()->PacketNumbersToAck), 3u);
    ASSERT_EQ(QuicRangeGetMax(&Ctx.Tracker()->PacketNumbersToAck), 4u);
}

//
// Test: OnAckFrameAcked removes all packets and clears ACK-eliciting count.
// Scenario: Adds packets 0-2, sets AckElicitingPacketsToAcknowledge > 0,
// then calls OnAckFrameAcked with largest=2. All packets are removed,
// HasPacketsToAck becomes FALSE, and the cleanup path should clear the count.
// Assertions: AckElicitingPacketsToAcknowledge=0, range empty.
//
TEST(AckTrackerTest, OnAckFrameAckedClearsElicitingCount)
{
    AckTrackerTestContext Ctx;

    for (uint64_t i = 0; i <= 2; i++) {
        QuicRangeAddValue(&Ctx.Tracker()->PacketNumbersToAck, i);
    }
    Ctx.Tracker()->AckElicitingPacketsToAcknowledge = 3;
    Ctx.Tracker()->AlreadyWrittenAckFrame = FALSE;

    QuicAckTrackerOnAckFrameAcked(Ctx.Tracker(), 2);

    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 0u);
    ASSERT_EQ(Ctx.Tracker()->AckElicitingPacketsToAcknowledge, 0u);
}

//
// Test: OnAckFrameAcked does not clear count when packets remain.
// Scenario: Adds packets 0-4 with gaps, calls OnAckFrameAcked with largest=2.
// Packets 3+ remain, so the cleanup path is not triggered.
// Assertions: AckElicitingPacketsToAcknowledge unchanged, remaining packets exist.
//
TEST(AckTrackerTest, OnAckFrameAckedRetainsCountWhenPacketsRemain)
{
    AckTrackerTestContext Ctx;

    for (uint64_t i = 0; i <= 4; i++) {
        QuicRangeAddValue(&Ctx.Tracker()->PacketNumbersToAck, i);
    }
    Ctx.Tracker()->AckElicitingPacketsToAcknowledge = 2;
    Ctx.Tracker()->AlreadyWrittenAckFrame = FALSE;

    QuicAckTrackerOnAckFrameAcked(Ctx.Tracker(), 2);

    //
    // Packets 3 and 4 remain. HasPacketsToAck should be TRUE, so the
    // cleanup path should not be triggered.
    //
    ASSERT_EQ(QuicRangeSize(&Ctx.Tracker()->PacketNumbersToAck), 1u);
    ASSERT_EQ(Ctx.Tracker()->AckElicitingPacketsToAcknowledge, 2u);
}
