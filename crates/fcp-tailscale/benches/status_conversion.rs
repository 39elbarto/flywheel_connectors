use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_tailscale::{PeerInfo, SelfNode, TailscaleStatus};

const PEER_COUNTS: [usize; 4] = [10, 100, 1_000, 10_000];

fn peer_info(index: usize) -> PeerInfo {
    let id = format!("node-{index}");
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
        tags: vec![
            "tag:fcp-work".to_string(),
            format!("tag:service-{index}"),
            "not-a-tag".to_string(),
            format!("tag:fcp-project-{index}"),
        ],
        online: index % 3 != 0,
        os: Some("linux".to_string()),
        last_seen: None,
    }
}

fn status_with_peers(peer_count: usize) -> TailscaleStatus {
    let peer = (0..peer_count)
        .map(|index| {
            let peer = peer_info(index);
            (peer.id.clone(), peer)
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
            tags: vec!["tag:fcp-owner".to_string()],
            online: true,
        },
        peer,
        user: None,
        tailnet: None,
    }
}

fn status_json(peer_count: usize) -> String {
    serde_json::to_string(&status_with_peers(peer_count))
        .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
}

fn parse_status_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("tailscale_status_parse_json");
    for peer_count in PEER_COUNTS {
        let json = status_json(peer_count);
        group.bench_function(format!("peers_{peer_count}"), |b| {
            b.iter(|| {
                std::hint::black_box(
                    serde_json::from_str::<TailscaleStatus>(&json)
                        .expect("synthetic status JSON is valid"),
                );
            });
        });
    }
    group.finish();
}

fn peer_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("tailscale_status_peer_conversion");
    for peer_count in PEER_COUNTS {
        let status = status_with_peers(peer_count);

        group.bench_function(format!("online_peer_filter_{peer_count}"), |b| {
            b.iter(|| {
                std::hint::black_box(
                    status
                        .clone()
                        .peer
                        .into_values()
                        .filter(|peer| peer.online)
                        .count(),
                );
            });
        });
        group.bench_function(format!("peers_map_conversion_{peer_count}"), |b| {
            b.iter(|| {
                std::hint::black_box(status.peers().expect("synthetic peer IDs are valid").len());
            });
        });
        group.bench_function(format!("allocating_fcp_tag_scan_{peer_count}"), |b| {
            b.iter(|| {
                std::hint::black_box(
                    status
                        .peer
                        .values()
                        .map(|peer| peer.fcp_tags().len())
                        .sum::<usize>(),
                );
            });
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
    targets = parse_status_json, peer_conversions
}
criterion_main!(benches);
