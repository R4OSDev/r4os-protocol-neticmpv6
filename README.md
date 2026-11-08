# NETICMP6

ICMPv6 and IPv6 pseudoheader wire codec.

NETICMP6 provides a stateless IPv6 pseudoheader checksum and bounded ICMPv6
parse, seal, echo-reply and error operations. Checksums include complete odd
byte tails. Input bounds, known message minima and error-to-error rules are
validated before a complete copied output record is published.

The codec accepts up to1504 upper-layer bytes. Generated ICMPv6 messages are
bounded to1240 bytes, matching the initial IPv6 owner's fixed1280-byte packet
limit. Parameter Problem errors preserve their exact pointer and bounded
quote. No NIC, route, neighbor, socket or mutable interface registry lives
here. A usable codec does not imply an IPv6 endpoint capability.

Build with `Build.sh` on Linux or `Build.bat` on Windows; `test` runs the
bounded component cases. `module.R4MF` owns module version, imports, profile,
dependencies and image placement. The pinned SDK selects the platform contract.

Normative contract: `Repositories/Contract/API/Ipv6Providers.txt` in the R4OS
workspace. `DOCUMENTATION.de.txt` records the provider boundary. Host codec,
controlled guest/peer and physical NIC/IRQ/DMA qualifications are separate.
Existing applications keep their current imports and operation.
