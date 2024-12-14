# WPA3 Handshake Wireshark Analysis Setup

## Color Filters Setup

1. Go to View → Coloring Rules
2. Add these rules (in order of priority):

```
# Handshake Components (Name | Filter | Background | Foreground)

"WPA3 SYN"
tcp.flags.syn == 1 && tcp.flags.ack == 0
#e6fff2 | #000000

"WPA3 SYN-ACK"
tcp.flags.syn == 1 && tcp.flags.ack == 1
#ccffeb | #000000

"WPA3 Nonce Exchange"
tcp.len == 32 || tcp.len == 38
#fff2cc | #000000

"WPA3 Encrypted Data"
tcp.len > 90
#e6ccff | #000000

"WPA3 Encrypted Response"
tcp.len > 60 && tcp.len < 90
#cce6ff | #000000

"WPA3 Connection End"
tcp.flags.fin == 1 || tcp.flags.reset == 1
#ffcccc | #000000
```

## Display Filters for Message Analysis

### 1. Handshake Components
```
# Initial TCP Handshake
tcp.flags.syn == 1 || tcp.flags.reset == 1

# Nonce Exchange
tcp.len == 32 || tcp.len == 38

# Encrypted Communications
tcp.len > 60
```

### 2. Message Flow Analysis
Add these columns:
- Right-click column header → Column Preferences
Add:
1. Time (Display Format: Seconds Since Previous Displayed Packet)
2. TCP Length
3. TCP Stream Sequence Number

## Packet Size Pattern Analysis

Based on your capture:

1. Initial Handshake:
   - 56 bytes: TCP SYN/SYN-ACK packets
   - 44 bytes: TCP ACK packets

2. WPA3 Messages:
   - 32 bytes: ANonce transfer
   - 76 bytes: PSH,ACK with initial data
   - 140 bytes: Encrypted messages (PSH,ACK)
   - 108 bytes: Encrypted responses
   - 44 bytes: ACK confirmations

## Timing Analysis Filters

```
# Find delays over 100ms
frame.time_delta > 0.1

# Group messages by exchange
tcp.flags.push == 1
```

## Custom Column Setup for Analysis

1. Right-click column header
2. Select "Column Preferences"
3. Add these columns:

```
Title          | Type
--------------------------------
Time Delta     | Delta time displayed
Length         | Packet length
TCP Flags      | TCP flags
TCP Length     | TCP payload length
Info          | Info column
```

## Message Identification Matrix

Message Type        | Direction      | Size Pattern        | Flags
-------------------|----------------|---------------------|----------------
ANonce             | Server→Client  | tcp.len == 32       | PSH,ACK
SNonce + MAC       | Client→Server  | tcp.len == 38       | PSH,ACK
Encrypted Message  | Either         | tcp.len > 90        | PSH,ACK
Encrypted Response | Either         | 60 < tcp.len < 90   | PSH,ACK
ACK                | Either         | tcp.len == 0        | ACK

## Analysis Tips

1. Message Flow Verification:
   ```
   tcp.flags.push == 1 && tcp.len > 0
   ```
   This shows only data-carrying packets.

2. Response Time Analysis:
   ```
   tcp.time_delta > 0.01
   ```
   Identifies potential processing delays.

3. Encryption Pattern:
   ```
   tcp.len > 60
   ```
   Shows only encrypted payloads.
