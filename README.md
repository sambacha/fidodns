## Pre-defined tunnel servers (Values 0-255)
The specification confirms only two pre-defined tunnel server domains are currently assigned:

```
Index 0: cable.ua5v.com (Google's tunnel server)
Index 1: cable.auth.com (Apple's tunnel server)
```
Values 0-255 are reserved for assigned domains, with the QR code including a field (key 2) indicating the number of assigned domains known to the implementation. This allows authenticators to determine whether a peer will recognize an assigned domain and potentially fall back to a hashed domain for compatibility.
```golang
govar assignedTunnelServerDomains = []string{"cable.ua5v.com", "cable.auth.com"}
```

### Hash-based domain generation algorithm (Values 256-65535)
For values ≥ 256, the specification provides the complete domain generation algorithm:
Algorithm Steps:


### Input Construction

> Create a specific byte sequence as SHA-256 input:

```golang
goshaInput := []byte{
  0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,  // "caBLEv2 "
  0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,  // "tunnel s"
  0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,  // "erver do"
  0x6d, 0x61, 0x69, 0x6e,                          // "main"
}
// Append the 16-bit value as two bytes (little-endian) plus a zero byte
shaInput = append(shaInput, byte(encoded), byte(encoded>>8), 0)

Hash Computation: Calculate SHA-256 of the input
godigest := sha256.Sum256(shaInput)
```
## Domain Construction:

- Extract first 8 bytes as little-endian uint64
- Use bottom 2 bits to select TLD from: .com, .org, .net, .info
- Right-shift by 2 bits
- Encode remaining bits using base32 alphabet: abcdefghijklmnopqrstuvwxyz234567
- Prepend with "cable." prefix



