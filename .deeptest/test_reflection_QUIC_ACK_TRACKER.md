# Test Reflection — QUIC_ACK_TRACKER

## Test: InitializeUninitialize
- **Scenario**: Verifies lifecycle of init/uninit
- **Primary API**: QuicAckTrackerInitialize, QuicAckTrackerUninitialize
- **Contract**: Both ranges initialized empty
- **Coverage**: Lines 47-58, 62-68
- **Non-redundancy**: Only test covering init/uninit pair

## Test: ResetClearsState
- **Scenario**: Reset after populating all fields
- **Primary API**: QuicAckTrackerReset
- **Contract**: All counters, flags, ECN data, and ranges zeroed
- **Coverage**: Lines 72-84
- **Non-redundancy**: Only test covering Reset function

## Tests: AddPacketNumber*
- **Scenario**: Duplicate detection via received range
- **Primary API**: QuicAckTrackerAddPacketNumber
- **Coverage**: Lines 88-97
- **Non-redundancy**: Each tests different duplicate/non-duplicate scenario

## Tests: HasPacketsToAck*
- **Scenario**: Inline helper checking range size + AlreadyWrittenAckFrame
- **Primary API**: QuicAckTrackerHasPacketsToAck
- **Coverage**: Header inline (lines 151-158)
- **Non-redundancy**: Tests empty, non-empty, and already-written states

## Tests: ReorderingThreshold*
- **Scenario**: RFC compliance for reordering detection
- **Primary API**: QuicAckTrackerDidHitReorderingThreshold
- **Coverage**: Lines 103-164 (all branches)
- **Non-redundancy**: 9 tests covering: threshold=0, single range, exceeded/not exceeded, LargestReported beyond range, multiple ranges, adjusted missing, loop exhaustion, clamping

## Tests: AckPacket*
- **Scenario**: Connection-dependent packet acknowledgment
- **Primary API**: QuicAckTrackerAckPacket
- **Coverage**: Lines 168-284 (partial - NON_ACK_ELICITING path, out-of-order, ECN, already-queued)
- **Non-redundancy**: Each tests distinct code path or ECN type

## Tests: OnAckFrameAcked*
- **Scenario**: Processing acknowledgment of sent ACK frames
- **Primary API**: QuicAckTrackerOnAckFrameAcked
- **Coverage**: Lines 340-367
- **Non-redundancy**: Tests range removal, cleanup path, and retention path
