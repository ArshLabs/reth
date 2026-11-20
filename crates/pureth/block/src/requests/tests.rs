use super::*;
use serde_json::Value;

fn reference() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/requests_gloas.json")).unwrap()
}

fn bytes(value: &Value) -> Bytes {
    value.as_str().unwrap().parse().unwrap()
}

#[test]
fn requests_match_independent_bytes_and_roots_and_reject_old_encoding() {
    for case in reference()["cases"].as_array().unwrap() {
        let encoded = bytes(&case["bytes"]);
        let groups =
            case["native_groups"].as_array().unwrap().iter().map(bytes).collect::<Vec<_>>();
        let snapshot = ExecutionRequestsSnapshot::from_native_groups(&groups).unwrap();
        assert_eq!(snapshot.serialized(), encoded.as_ref());
        assert_eq!(snapshot.root(), case["root"].as_str().unwrap().parse::<B256>().unwrap());
        let decoded = ExecutionRequestsSnapshot::from_ssz(&encoded).unwrap();
        assert_eq!(decoded.requests(), snapshot.requests());
        assert_eq!(decoded.root(), snapshot.root());
        if let Some(root) = case["electra_root"].as_str() {
            assert_ne!(root.parse::<B256>().unwrap(), snapshot.root());
            assert!(ExecutionRequestsSnapshot::from_ssz(&bytes(&case["electra_bytes"])).is_err());
        }
    }
}

#[test]
fn gloas_request_groups_reject_unknown_duplicate_unordered_and_malformed_records() {
    for groups in [
        vec![Bytes::new()],
        vec![Bytes::from_static(&[3])],
        vec![Bytes::from_static(&[5, 0])],
        vec![Bytes::from_static(&[255, 0])],
    ] {
        assert!(ExecutionRequestsSnapshot::from_native_groups(&groups).is_err());
    }
    for (tag, width, maximum) in [
        (0, 192, None),
        (1, 76, Some(16)),
        (2, 116, Some(2)),
        (3, 184, Some(64)),
        (4, 68, Some(16)),
    ] {
        let mut valid = vec![tag];
        valid.resize(width + 1, 0);
        let valid = Bytes::from(valid);
        assert!(ExecutionRequestsSnapshot::from_native_groups(std::slice::from_ref(&valid)).is_ok());
        assert!(
            ExecutionRequestsSnapshot::from_native_groups(&[valid.clone(), valid.clone()]).is_err()
        );
        let mut short = valid.to_vec();
        short.pop();
        assert!(ExecutionRequestsSnapshot::from_native_groups(&[short.into()]).is_err());
        if let Some(maximum) = maximum {
            let mut oversized = vec![tag];
            oversized.resize(1 + width * (maximum + 1), 0);
            assert!(ExecutionRequestsSnapshot::from_native_groups(&[oversized.into()]).is_err());
        }
    }
    let mut deposit = vec![3];
    deposit.resize(185, 0);
    let mut exit = vec![4];
    exit.resize(69, 0);
    assert!(ExecutionRequestsSnapshot::from_native_groups(&[exit.into(), deposit.into()]).is_err());
}

#[test]
fn gloas_request_decoder_rejects_invalid_offsets_and_builder_counts() {
    let reference = reference();
    let encoded = bytes(&reference["cases"][2]["bytes"]);
    for (position, offset) in [(0, 16), (0, 24), (4, 19), (8, u32::MAX)] {
        let mut changed = encoded.to_vec();
        changed[position..position + 4].copy_from_slice(&offset.to_le_bytes());
        assert!(ExecutionRequestsSnapshot::from_ssz(&changed).is_err());
    }
    for requests in [
        ExecutionRequests {
            builder_deposits: vec![BuilderDepositRequest::default(); 65],
            ..Default::default()
        },
        ExecutionRequests {
            builder_exits: vec![BuilderExitRequest::default(); 17],
            ..Default::default()
        },
    ] {
        assert!(requests.to_ssz_bytes().is_err());
        assert!(requests.tree().is_err());
    }
}

#[test]
fn gloas_deposits_do_not_inherit_the_electra_schema_limit() {
    let reference = reference();
    let boundary = &reference["unbounded_deposits"];
    let count = boundary["count"].as_u64().unwrap() as usize;
    let mut group = vec![0];
    group.resize(1 + count * 192, 0);
    let groups = [Bytes::from(group)];
    let snapshot = ExecutionRequestsSnapshot::from_native_groups(&groups).unwrap();
    assert_eq!(snapshot.requests().deposits.len(), count);
    assert_eq!(snapshot.root(), boundary["root"].as_str().unwrap().parse::<B256>().unwrap());
    let decoded = ExecutionRequestsSnapshot::from_ssz(snapshot.serialized()).unwrap();
    assert_eq!(decoded.root(), snapshot.root());
}
