//! Local non-mock acceptance coverage for the FCP Redis connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use fcp_redis::connector::RedisConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "redis";
const FIXTURE_ID: &str = "redis-loopback-upstash-rest-acceptance";
const TEST_TOKEN: &str = "redis-local-non-mock-token";
const STRING_KEY: &str = "fcp:redis:acceptance:string";
const COUNTER_KEY: &str = "fcp:redis:acceptance:counter";
const HASH_KEY: &str = "fcp:redis:acceptance:hash";
const LIST_KEY: &str = "fcp:redis:acceptance:list";
const SET_KEY: &str = "fcp:redis:acceptance:set";

#[derive(Debug)]
struct FixtureObservation {
    request_lines: Vec<String>,
    commands: Vec<Vec<String>>,
    authorization_count: usize,
    json_content_type_count: usize,
}

struct LoopbackRedisFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

#[derive(Default)]
struct RedisFixtureState {
    strings: HashMap<String, String>,
    ttl_seconds: HashMap<String, i64>,
    hashes: HashMap<String, BTreeMap<String, String>>,
    lists: HashMap<String, VecDeque<String>>,
    sets: HashMap<String, BTreeSet<String>>,
}

impl LoopbackRedisFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set loopback listener nonblocking");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || run_server(&listener, expected_requests));

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn run_server(listener: &TcpListener, expected_requests: usize) -> FixtureObservation {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut state = RedisFixtureState::default();
    let mut observation = FixtureObservation {
        request_lines: Vec::with_capacity(expected_requests),
        commands: Vec::with_capacity(expected_requests),
        authorization_count: 0,
        json_content_type_count: 0,
    };

    while observation.commands.len() < expected_requests {
        match listener.accept() {
            Ok((stream, _)) => handle_request(stream, &mut state, &mut observation),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for Redis connector request {} of {expected_requests}",
                    observation.commands.len() + 1
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept Redis connector request: {error}"),
        }
    }

    observation
}

fn handle_request(
    mut stream: TcpStream,
    state: &mut RedisFixtureState,
    observation: &mut FixtureObservation,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let headers = request
        .split_once("\r\n\r\n")
        .map_or(request.as_str(), |(headers, _)| headers);
    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer redis-local-non-mock-token"))
    {
        observation.authorization_count += 1;
    }
    if headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("content-type:") && lower.contains("application/json")
    }) {
        observation.json_content_type_count += 1;
    }

    let body = request
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body.trim_end_matches('\0'));
    let command: Vec<String> = serde_json::from_str(body).expect("parse Redis command body");
    let response = execute_command(state, &command);

    observation.request_lines.push(request_line);
    observation.commands.push(command);
    write_json_response(&mut stream, &response);
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut scratch).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&scratch[..bytes_read]);

        if let Some(headers_end) = find_subslice(&buffer, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if buffer.len() >= headers_end + 4 + content_length {
                break;
            }
        }
    }

    String::from_utf8_lossy(&buffer).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_json_response(stream: &mut TcpStream, body: &Value) {
    let body = body.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("write Redis fixture response");
}

fn execute_command(state: &mut RedisFixtureState, command: &[String]) -> Value {
    let Some(op) = command.first().map(String::as_str) else {
        return json!({ "error": "empty command" });
    };

    match op {
        "SET" => command_set(state, command),
        "GET" => json!({ "result": state.strings.get(&command[1]).cloned() }),
        "EXISTS" => {
            json!({ "result": command[1..].iter().filter(|key| state.exists(key)).count() })
        }
        "TTL" => json!({ "result": state.ttl_seconds.get(&command[1]).copied().unwrap_or(-1) }),
        "EXPIRE" => {
            let seconds = command[2].parse::<i64>().expect("parse EXPIRE seconds");
            let exists = state.exists(&command[1]);
            if exists {
                state.ttl_seconds.insert(command[1].clone(), seconds);
            }
            json!({ "result": i64::from(exists) })
        }
        "INCR" => {
            let current = state
                .strings
                .get(&command[1])
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0)
                + 1;
            state
                .strings
                .insert(command[1].clone(), current.to_string());
            json!({ "result": current })
        }
        "HSET" => command_hset(state, command),
        "HGET" => json!({
            "result": state
                .hashes
                .get(&command[1])
                .and_then(|fields| fields.get(&command[2]))
                .cloned()
        }),
        "HGETALL" => {
            json!({ "result": state.hashes.get(&command[1]).cloned().unwrap_or_default() })
        }
        "LPUSH" => command_lpush(state, command),
        "LRANGE" => command_lrange(state, command),
        "SADD" => command_sadd(state, command),
        "SMEMBERS" => json!({
            "result": state
                .sets
                .get(&command[1])
                .map(|members| members.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        }),
        "DEL" => json!({ "result": command[1..].iter().filter(|key| state.del(key)).count() }),
        other => json!({ "error": format!("unsupported command {other}") }),
    }
}

impl RedisFixtureState {
    fn exists(&self, key: &str) -> bool {
        self.strings.contains_key(key)
            || self.hashes.contains_key(key)
            || self.lists.contains_key(key)
            || self.sets.contains_key(key)
    }

    fn del(&mut self, key: &str) -> bool {
        let mut deleted = self.strings.remove(key).is_some();
        deleted |= self.ttl_seconds.remove(key).is_some();
        deleted |= self.hashes.remove(key).is_some();
        deleted |= self.lists.remove(key).is_some();
        deleted |= self.sets.remove(key).is_some();
        deleted
    }
}

fn command_set(state: &mut RedisFixtureState, command: &[String]) -> Value {
    let key = command[1].clone();
    let value = command[2].clone();
    let mut ttl = None;
    let mut mode = None;
    let mut index = 3;
    while index < command.len() {
        match command[index].as_str() {
            "EX" => {
                ttl = Some(
                    command[index + 1]
                        .parse::<i64>()
                        .expect("parse SET EX seconds"),
                );
                index += 2;
            }
            "NX" | "XX" => {
                mode = Some(command[index].as_str());
                index += 1;
            }
            other => panic!("unexpected SET option {other}"),
        }
    }

    let key_exists = state.exists(&key);
    if mode == Some("NX") && key_exists || mode == Some("XX") && !key_exists {
        return json!({ "result": Value::Null });
    }
    state.strings.insert(key.clone(), value);
    if let Some(seconds) = ttl {
        state.ttl_seconds.insert(key, seconds);
    }
    json!({ "result": "OK" })
}

fn command_hset(state: &mut RedisFixtureState, command: &[String]) -> Value {
    let fields = state.hashes.entry(command[1].clone()).or_default();
    let mut created = 0_i64;
    for pair in command[2..].chunks_exact(2) {
        if !fields.contains_key(&pair[0]) {
            created += 1;
        }
        fields.insert(pair[0].clone(), pair[1].clone());
    }
    json!({ "result": created })
}

fn command_lpush(state: &mut RedisFixtureState, command: &[String]) -> Value {
    let list = state.lists.entry(command[1].clone()).or_default();
    for element in &command[2..] {
        list.push_front(element.clone());
    }
    json!({ "result": list.len() })
}

fn command_lrange(state: &RedisFixtureState, command: &[String]) -> Value {
    let list = state.lists.get(&command[1]).cloned().unwrap_or_default();
    let start = command[2].parse::<isize>().expect("parse LRANGE start");
    let stop = command[3].parse::<isize>().expect("parse LRANGE stop");
    let len = isize::try_from(list.len()).expect("list length fits isize");
    let start = if start < 0 { len + start } else { start }.clamp(0, len);
    let stop = if stop < 0 { len + stop } else { stop }.clamp(-1, len - 1);

    let values = if start > stop {
        Vec::new()
    } else {
        list.into_iter()
            .skip(usize::try_from(start).expect("start nonnegative"))
            .take(usize::try_from(stop - start + 1).expect("range length nonnegative"))
            .collect::<Vec<_>>()
    };
    json!({ "result": values })
}

fn command_sadd(state: &mut RedisFixtureState, command: &[String]) -> Value {
    let set = state.sets.entry(command[1].clone()).or_default();
    let mut added = 0_i64;
    for member in &command[2..] {
        if set.insert(member.clone()) {
            added += 1;
        }
    }
    json!({ "result": added })
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::KeyValue,
        "upstash-compatible-loopback-http",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "redis-rest-loopback-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-redis-rest-port",
        10_000,
        "local Upstash-compatible HTTP command endpoint accepts production connector traffic",
    ))
    .with_seed(FixtureSeedRecord::new(
        STRING_KEY,
        "initial",
        json!({ "value": "value" }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "redis-family-mutations",
            "loopback-redis-state",
            "string-hash-list-set-counter",
            "connector writes strings, counters, hashes, lists, and sets through the REST command boundary",
        )
        .with_before(json!({ "keys": 0 }))
        .with_after(json!({ "keys": 5 })),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-keys",
        "loopback-redis-state",
        "key_absence_after_del",
        "all acceptance keys are absent after redis.del cleanup",
    ))
}

async fn configured_connector(base_url: &str) -> RedisConnector {
    let mut connector = RedisConnector::new();
    connector
        .handle_configure(json!({
            "api_token": TEST_TOKEN,
            "base_url": base_url,
        }))
        .await
        .expect("configure Redis connector");
    connector
        .handle_handshake(json!({"session_id": "redis-local-non-mock"}))
        .await
        .expect("handshake Redis connector");
    connector
}

async fn invoke(connector: &RedisConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("Redis loopback fixture should satisfy operation")
}

#[fcp_async_core::runtime::test]
async fn redis_connector_acceptance_exercises_upstash_rest_loopback_boundary() {
    let fixture = LoopbackRedisFixture::start(15);
    let connector = configured_connector(fixture.base_url()).await;
    let fixture_contract = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture_contract);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");

    let set = invoke(
        &connector,
        "redis.set",
        json!({
            "key": STRING_KEY,
            "value": "value",
            "ttl_seconds": 60,
            "nx": true
        }),
    )
    .await;
    assert_eq!(set["result"], "OK");

    let get = invoke(&connector, "redis.get", json!({ "key": STRING_KEY })).await;
    assert_eq!(get["value"], "value");

    let exists = invoke(
        &connector,
        "redis.exists",
        json!({ "keys": [STRING_KEY, HASH_KEY] }),
    )
    .await;
    assert_eq!(exists["count"], 1);

    let ttl = invoke(&connector, "redis.ttl", json!({ "key": STRING_KEY })).await;
    assert_eq!(ttl["ttl"], 60);

    let expire = invoke(
        &connector,
        "redis.expire",
        json!({ "key": STRING_KEY, "seconds": 120 }),
    )
    .await;
    assert_eq!(expire["result"], 1);

    let incr = invoke(&connector, "redis.incr", json!({ "key": COUNTER_KEY })).await;
    assert_eq!(incr["value"], 1);

    let hset = invoke(
        &connector,
        "redis.hset",
        json!({ "key": HASH_KEY, "fields": { "field": "hash-value" } }),
    )
    .await;
    assert_eq!(hset["result"], 1);
    let hget = invoke(
        &connector,
        "redis.hget",
        json!({ "key": HASH_KEY, "field": "field" }),
    )
    .await;
    assert_eq!(hget["value"], "hash-value");
    let hgetall = invoke(&connector, "redis.hgetall", json!({ "key": HASH_KEY })).await;
    assert_eq!(hgetall["fields"]["field"], "hash-value");

    let lpush = invoke(
        &connector,
        "redis.lpush",
        json!({ "key": LIST_KEY, "elements": ["first", "second"] }),
    )
    .await;
    assert_eq!(lpush["length"], 2);
    let lrange = invoke(&connector, "redis.lrange", json!({ "key": LIST_KEY })).await;
    assert_eq!(lrange["values"], json!(["second", "first"]));

    let sadd = invoke(
        &connector,
        "redis.sadd",
        json!({ "key": SET_KEY, "members": ["member-a", "member-b"] }),
    )
    .await;
    assert_eq!(sadd["added"], 2);
    let smembers = invoke(&connector, "redis.smembers", json!({ "key": SET_KEY })).await;
    assert_eq!(smembers["members"], json!(["member-a", "member-b"]));

    let deleted = invoke(
        &connector,
        "redis.del",
        json!({ "keys": [STRING_KEY, COUNTER_KEY, HASH_KEY, LIST_KEY, SET_KEY] }),
    )
    .await;
    assert_eq!(deleted["deleted"], 5);
    let cleanup_exists = invoke(
        &connector,
        "redis.exists",
        json!({ "keys": [STRING_KEY, COUNTER_KEY, HASH_KEY, LIST_KEY, SET_KEY] }),
    )
    .await;
    assert_eq!(cleanup_exists["count"], 0);

    let observation = fixture.join();
    assert_eq!(observation.commands.len(), 15);
    assert_eq!(observation.authorization_count, observation.commands.len());
    assert_eq!(
        observation.json_content_type_count,
        observation.commands.len()
    );
    assert_eq!(
        observation.commands[0],
        ["SET", STRING_KEY, "value", "EX", "60", "NX"]
    );
    assert_eq!(observation.commands[1], ["GET", STRING_KEY]);
    assert_eq!(observation.commands[14][0], "EXISTS");

    let cleanup = CleanupVerificationResult::new(
        "cleanup-keys",
        "fcp:redis:acceptance:*",
        "key_absence_after_del",
        "all acceptance keys are absent after redis.del cleanup",
        json!({ "exists_after_delete": 0 }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-redis-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "fixture_mode": "loopback_http",
        "transport": "upstash-compatible-redis-rest",
        "operations": [
            "redis.set",
            "redis.get",
            "redis.exists",
            "redis.ttl",
            "redis.expire",
            "redis.incr",
            "redis.hset",
            "redis.hget",
            "redis.hgetall",
            "redis.lpush",
            "redis.lrange",
            "redis.sadd",
            "redis.smembers",
            "redis.del",
            "redis.exists:cleanup"
        ],
        "request_lines": observation.request_lines,
        "authorization_seen_for_all_requests": observation.authorization_count == observation.commands.len(),
        "json_content_type_seen_for_all_requests": observation.json_content_type_count == observation.commands.len(),
        "fixture_contract": fixture_contract.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(TEST_TOKEN),
        "acceptance evidence must not expose Redis token"
    );
}
