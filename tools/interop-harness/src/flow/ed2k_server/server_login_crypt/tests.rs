//! The login-classification and verdict legs of the server-login crypt flow.

use super::*;

fn plain_login() -> Vec<u8> {
    // protocol, 4-byte length, OP_LOGINREQUEST, then the body
    let mut frame = vec![0xE3, 0x55, 0, 0, 0, 0x01];
    frame.extend_from_slice(&[0; 0x54]);
    frame
}

/// The login is told by its opening, not its place in the capture: a plain
/// `OP_LOGINREQUEST`, an obfuscated opening, and a plain frame that is no
/// login (the hello a port test is answered with) each read as what they
/// are.
#[test]
fn a_login_is_told_by_its_first_frame() {
    assert_eq!(LoginKind::of(&plain_login()), Some(LoginKind::Plain));

    let mut obfuscated = vec![0x1F];
    obfuscated.extend_from_slice(&[0xAB; 101]);
    assert_eq!(LoginKind::of(&obfuscated), Some(LoginKind::Obfuscated));

    let hello_answer = [0xE3, 0x10, 0, 0, 0, 0x4C, 1, 2, 3];
    assert_eq!(
        LoginKind::of(&hello_answer),
        None,
        "a protocol frame that is no login"
    );
    assert_eq!(
        LoginKind::of(&[0x1F, 0x01]),
        None,
        "too short to be an opening"
    );
    assert_eq!(LoginKind::of(&[]), None);
}

fn frame(protocol: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![protocol];
    bytes.extend_from_slice(&(payload.len() as u32 + 1).to_le_bytes());
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    bytes
}

/// The server's plain answer is walked frame by frame: a message ahead of
/// the `OP_IDCHANGE` does not hide it, and its payload size tells whether
/// the size-20 extension came.
#[test]
fn the_id_change_size_is_read_past_earlier_frames() {
    let mut stream = frame(0xE3, 0x38, b"welcome");
    stream.extend(frame(0xE3, OP_IDCHANGE, &[0; 20]));
    assert_eq!(id_change_payload_len(&stream), Some(20));

    let short = frame(0xE3, OP_IDCHANGE, &[0; 8]);
    assert_eq!(id_change_payload_len(&short), Some(8));

    let mut no_change = frame(0xE3, 0x38, b"welcome");
    no_change.extend_from_slice(&[0x1F, 0x99, 0xAB]);
    assert_eq!(id_change_payload_len(&no_change), None);
}

/// The by-name proof needs the first link plain for the stated reason and
/// answered, with a second dial after it.
#[test]
fn the_by_name_proof_reads_the_first_dial() {
    let log = "server.login server=s:4661 step=link_chosen link=plain why=server_not_known_to_obfuscate\n\
               server.login server=s:4661 step=answered id=1\n\
               server.login server=s:4661 step=link_chosen link=obfuscated port=4661\n";
    assert!(first_dial_was_plain_unknown(&dials(log)));

    let unanswered = log.replace("step=answered id=1", "step=sent");
    assert!(!first_dial_was_plain_unknown(&dials(&unanswered)));

    let known = log.replace("why=server_not_known_to_obfuscate", "why=policy_off");
    assert!(!first_dial_was_plain_unknown(&dials(&known)));
}

/// Score a retained run again without driving the flow:
/// `RMULE_BENCH_VERDICT_DIR=<run dir> RMULE_BENCH_POLICY=<policy> cargo test
/// -p rmule-interop-harness --lib rescore -- --ignored --nocapture`.
#[test]
#[ignore = "scores a retained bench run named by RMULE_BENCH_VERDICT_DIR"]
fn rescore_a_retained_run() {
    let dir = std::env::var("RMULE_BENCH_VERDICT_DIR").expect("RMULE_BENCH_VERDICT_DIR");
    let policy = std::env::var("RMULE_BENCH_POLICY").unwrap_or_else(|_| "requested".into());
    let root = std::path::Path::new(&dir).join("server-login-crypt");
    let logs = fs::read_to_string(root.join("rmule.log")).expect("rmule.log");
    // A by-name run logs the server's name, so it names its address.
    let by_name = std::env::var("RMULE_BENCH_SERVER_IP").ok();
    let server: IpAddr = by_name
        .clone()
        .or_else(|| {
            logs.split("server=")
                .nth(1)
                .and_then(|rest| rest.split(':').next())
                .map(str::to_owned)
        })
        .and_then(|ip| ip.parse().ok())
        .expect("the server address in rmule.log, or RMULE_BENCH_SERVER_IP");
    let initiates = matches!(policy.as_str(), "requested" | "required");
    let line = verdict(
        &policy,
        initiates,
        by_name.is_some(),
        &logs,
        &root.join(PCAP),
        server,
    )
    .expect("scored");
    println!("{line}");
}
