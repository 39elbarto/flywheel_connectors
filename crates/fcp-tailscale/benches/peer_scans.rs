use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_tailscale::{PeerInfo, SelfNode, TailscaleStatus};

const SIZES: [usize; 4] = [10, 100, 1_000, 10_000];

fn peer_with_tags(tag_count: usize) -> PeerInfo {
    let tags = (0..tag_count)
        .map(|index| match index % 4 {
            0 => format!("tag:fcp-zone-{index}"),
            1 => format!("tag:service-{index}"),
            2 => format!("not-a-tag-{index}"),
            _ => format!("tag:fcp-project-{index}"),
        })
        .collect();

    PeerInfo {
        id: "node-0".to_string(),
        public_key: "pubkey:node-0".to_string(),
        host_name: "host-0".to_string(),
        dns_name: "host-0.tailnet.example".to_string(),
        tailscale_ips: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
        tags,
        online: true,
        os: Some("linux".to_string()),
        last_seen: None,
    }
}

fn status_with_peers(peer_count: usize) -> TailscaleStatus {
    let peer = (0..peer_count)
        .map(|index| {
            let id = format!("node-{index}");
            (
                id.clone(),
                PeerInfo {
                    id: id.clone(),
                    public_key: format!("pubkey:{id}"),
                    host_name: format!("host-{index}"),
                    dns_name: format!("host-{index}.tailnet.example"),
                    tailscale_ips: vec![IpAddr::V4(Ipv4Addr::new(
                        100,
                        64,
                        u8::try_from((index / 256) % 256).unwrap_or(0),
                        u8::try_from(index % 256).unwrap_or(0),
                    ))],
                    tags: vec!["tag:fcp-work".to_string(), "tag:server".to_string()],
                    online: true,
                    os: Some("linux".to_string()),
                    last_seen: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    TailscaleStatus {
        backend_state: "Running".to_string(),
        self_node: SelfNode {
            id: "self-node".to_string(),
            public_key: "pubkey:self-node".to_string(),
            host_name: "self-host".to_string(),
            dns_name: "self-host.tailnet.example".to_string(),
            tailscale_ips: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 255, 1))],
            tags: Vec::new(),
            online: true,
        },
        peer,
        user: None,
        tailnet: None,
    }
}

fn peer_tag_scans(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_tag_scans");
    for size in SIZES {
        let peer = peer_with_tags(size);
        group.bench_function(format!("borrowed_fcp_tag_strs_{size}"), |b| {
            b.iter(|| std::hint::black_box(peer.iter_fcp_tag_strs().count()));
        });
        group.bench_function(format!("allocating_fcp_tags_{size}"), |b| {
            b.iter(|| std::hint::black_box(peer.fcp_tags().len()));
        });
    }
    group.finish();
}

fn status_peer_scans(c: &mut Criterion) {
    let mut group = c.benchmark_group("status_peer_scans");
    for size in SIZES {
        let status = status_with_peers(size);
        group.bench_function(format!("borrowed_validate_peer_ids_{size}"), |b| {
            b.iter(|| std::hint::black_box(status.validate_peer_ids().unwrap()));
        });
        group.bench_function(format!("allocating_peers_map_{size}"), |b| {
            b.iter(|| std::hint::black_box(status.peers().unwrap().len()));
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_millis(100))
        .measurement_time(std::time::Duration::from_millis(500));
    targets = peer_tag_scans, status_peer_scans
}
criterion_main!(benches);
