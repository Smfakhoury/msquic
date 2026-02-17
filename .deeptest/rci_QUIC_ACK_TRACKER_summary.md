# Repository Contract Index — QUIC_ACK_TRACKER

## Public API Inventory

### Standalone (no Connection dependency)
| Function | Summary |
|----------|---------|
| `QuicAckTrackerInitialize` | Init both ranges |
| `QuicAckTrackerUninitialize` | Free range resources |
| `QuicAckTrackerReset` | Zero all state, reset ranges |
| `QuicAckTrackerAddPacketNumber` | Add to received set; TRUE = duplicate |
| `QuicAckTrackerDidHitReorderingThreshold` | Check reordering threshold per RFC |
| `QuicAckTrackerHasPacketsToAck` | Check if packets need ACK frame |

### Connection-dependent (require QUIC_PACKET_SPACE + QUIC_CONNECTION)
| Function | Summary |
|----------|---------|
| `QuicAckTrackerAckPacket` | Mark packet for ACK, handle ECN, trigger send |
| `QuicAckTrackerAckFrameEncode` | Encode ACK frame into packet builder |
| `QuicAckTrackerOnAckFrameAcked` | Process ACK of our ACK frame |

## Key State Machine
- Init → Ready (ranges initialized, counters zero)
- Ready → Tracking (AddPacketNumber / AckPacket adds packets)
- Tracking → AckWritten (AckFrameEncode sets AlreadyWrittenAckFrame)
- AckWritten → Tracking (new packet clears AlreadyWrittenAckFrame)
- Any → Reset (QuicAckTrackerReset returns to Ready)
- Any → Uninit (QuicAckTrackerUninitialize)

## Dependency Map
- `QuicAckTrackerGetPacketSpace` — CXPLAT_CONTAINING_RECORD back to QUIC_PACKET_SPACE
- Connection->Send — for ACK flag management
- QUIC_RANGE — underlying data structure for packet number tracking
