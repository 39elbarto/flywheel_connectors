# Healthy Mesh Peer Definition

A healthy mesh peer for V2 mesh-native host boot is a peer that satisfies both
conditions:

- it emitted a valid heartbeat within the last 30 seconds
- its gossip signature verifies against a known `NodeKeyAttestation`

The healthy-peer count is exclusive of the local host. The default minimum for
V2 active mode is one healthy peer, configured by
`FCP_V2_MIN_HEALTHY_MESH_PEERS`. Zero healthy peers keeps the host in evaluation
mode because the host cannot distinguish a real mesh from an isolated single
host.

The boot-time check runs after the host mesh-handshake phase and before the host
accepts `/rpc/invoke` requests. When live peer state is not yet wired into
`AppState`, fcp-host classifies the boundary as zero healthy peers and applies
the insufficient-peer behavior mechanically.
