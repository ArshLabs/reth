use super::*;
use alloy_consensus::TxEip1559;
use alloy_primitives::{b256, uint, Address};

#[test]
fn legacy_call_bytes_and_hashes_match_pinned_reference() {
    for (selector, rlp, ssz, signing_hash, transaction_hash, object_root) in [
        (
            1_u8,
            "f86780862d79883d2000825208945df9b87991262f6ba471f09758cde1c0fc1de734827a69801ca088ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0a045e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a",
            "08000000720000000100000000000000000000203d88792d000000000000000000000000000000000000000000000000000008520000000000005df9b87991262f6ba471f09758cde1c0fc1de734697a000000000000000000000000000000000000000000000000000000000000690000000088ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d045e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a01",
            b256!("19b1e28c14f33e74b96b88eba97d4a4fc8a97638d72e972310025b7e1189b049"),
            b256!("5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"),
            b256!("bef7b49904562eac794ae36b9e675e46d638bc4121453f9a46bbe03473d1ab87"),
        ),
        (
            1_u8,
            "f86e8243eb850df847580082c35094df190dc7190dfba737d7777a163445b7fff161338806113a84987be800801ca03b08715b4403c792b8c7567edea634088bedcd7f60d9352b1f16c69830f3afd5a010b9afb67d2ec8b956f0e1dbc07eb79152904f3a7bf789fc869db56320adfe09",
            "08000000720000000100eb43000000000000005847f80d00000000000000000000000000000000000000000000000000000050c3000000000000df190dc7190dfba737d7777a163445b7fff1613300e87b98843a110600000000000000000000000000000000000000000000000069000000003b08715b4403c792b8c7567edea634088bedcd7f60d9352b1f16c69830f3afd510b9afb67d2ec8b956f0e1dbc07eb79152904f3a7bf789fc869db56320adfe0901",
            b256!("05887873a4fc88813466382673be81701adc8f564f7bcd17e2ce974a43100d04"),
            b256!("e9e91f1ee4b56c0df2e9f06c2b8c27c6076195a88a7b8537ba8313d80e6f124e"),
            b256!("b5fd697f31a68d85d6502a137b11548302dffa23b1954aa6b12d105599a82ad2"),
        ),
        (
            3_u8,
            "f88b822ecd8509839089a083015f909484654be796dad370032391d5479f8f1fd9ddd14e80a4d508e62389272d541e4168e5303b5838dcef5f9ac769a057f8dc6aabce7ec1e69b7ce5e625a078e88f9c69d217c76d92d5472f5812501021342f0054178c0579ee532dc2a218a0484723f0933633a6c213fc201ee3aecbe919579377b11a79acd887950a068e33",
            "08000000b600000003000100000000000000000000000000000000000000000000000000000000000000cd2e000000000000a089908309000000000000000000000000000000000000000000000000000000905f01000000000084654be796dad370032391d5479f8f1fd9ddd14e000000000000000000000000000000000000000000000000000000000000000089000000d508e62389272d541e4168e5303b5838dcef5f9ac769a057f8dc6aabce7ec1e69b7ce5e60078e88f9c69d217c76d92d5472f5812501021342f0054178c0579ee532dc2a218484723f0933633a6c213fc201ee3aecbe919579377b11a79acd887950a068e3300",
            b256!("3e4c94ee2d68abe91ab5c97ad1111f5367a8cbdc8e907850ff9a297a11755441"),
            b256!("dc81918bf78322ce017c592e81c855f40bb96bd82da9779167de1de109962be6"),
            b256!("ad2afaa33122dd0c7a4c18f600f18d256cfe503dab5b2e24e0029455109f89cd"),
        ),
    ] {
        let rlp = alloy_primitives::hex::decode(rlp).unwrap();
        let ssz = alloy_primitives::hex::decode(ssz).unwrap();
        let transaction = TransactionSsz::from_rlp(&rlp).unwrap();
        assert_eq!(transaction.selector(), selector);
        assert_eq!(encode_transaction(&transaction).unwrap(), ssz);
        assert_eq!(decode_transaction(&ssz).unwrap(), transaction);
        assert_eq!(transaction.original_rlp().unwrap().as_ref(), rlp);
        assert_eq!(transaction.original_signing_hash().unwrap(), signing_hash);
        assert_eq!(transaction.original_transaction_hash().unwrap(), transaction_hash);
        let snapshot = TransactionSnapshot::build(vec![transaction]).unwrap();
        assert_eq!(snapshot.transaction_tree(0).unwrap().root(), object_root);
    }
}

fn signature() -> Signature {
    Signature::new(
        uint!(0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0_U256),
        uint!(0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a_U256),
        true,
    )
}

fn transaction(chain_id: Option<U256>, to: TxKind) -> TransactionSsz {
    TransactionSsz::new(
        LegacyPayload {
            chain_id,
            nonce: 9,
            gas_price: U256::from(20_000_000_000_u64),
            gas_limit: 53_000,
            to,
            value: U256::from(7),
            input: Bytes::from(vec![0x01, 0x02, 0x03]),
        },
        signature(),
    )
    .unwrap()
}

fn four_variants() -> Vec<TransactionSsz> {
    let call = TxKind::Call(Address::repeat_byte(0x11));
    vec![
        transaction(None, call),
        transaction(None, TxKind::Create),
        transaction(Some(U256::from(1)), call),
        transaction(Some(U256::from(1)), TxKind::Create),
    ]
}

#[test]
fn four_variants_preserve_canonical_bytes_rlp_and_hashes() {
    let roots = [
        b256!("73ceedc325e607a90ca880e0efed4eca06837e5083c6f26034766c10b7bfc21b"),
        b256!("cfdbf09099661b05b05b46dd65560055c7d1290d5f98252748661ad21906d47a"),
        b256!("b5ffccfdabe1828d188d15196b5a23ea4eac490374301134d2b29e04b6a04aca"),
        b256!("cc0652f06794faa3f6c4959bcb9945886ebea807f8fc0c55aa47086d03c32ae4"),
    ];
    for (index, (transaction, expected_root)) in four_variants().into_iter().zip(roots).enumerate()
    {
        assert_eq!(usize::from(transaction.selector()), index + 1);
        let bytes = encode_transaction(&transaction).unwrap();
        let decoded = decode_transaction(&bytes).unwrap();
        assert_eq!(decoded, transaction);
        assert_eq!(encode_transaction(&decoded).unwrap(), bytes);

        let original = transaction.to_alloy().unwrap();
        let rlp = transaction.original_rlp().unwrap();
        assert_eq!(TransactionSsz::from_alloy(&original).unwrap(), transaction);
        assert_eq!(TransactionSsz::from_rlp(&rlp).unwrap(), transaction);
        assert_eq!(transaction.original_transaction_hash().unwrap(), *original.hash());
        assert_eq!(transaction.original_signing_hash().unwrap(), original.signature_hash());
        let snapshot = TransactionSnapshot::build(vec![transaction]).unwrap();
        assert_eq!(snapshot.transaction_tree(0).unwrap().root(), expected_root);
    }
}

#[test]
fn optional_fields_distinguish_absence_from_zero() {
    let variants = vec![
        transaction(None, TxKind::Create),
        transaction(None, TxKind::Call(Address::ZERO)),
        transaction(Some(U256::ZERO), TxKind::Create),
        transaction(Some(U256::ZERO), TxKind::Call(Address::ZERO)),
    ];
    let snapshot = TransactionSnapshot::build(variants).unwrap();
    for left in 0..4 {
        for right in left + 1..4 {
            assert_ne!(
                snapshot.transaction_tree(left).unwrap().root(),
                snapshot.transaction_tree(right).unwrap().root(),
            );
        }
    }
}

#[test]
fn list_snapshot_preserves_order_and_retained_transaction_access() {
    for (count, expected_root) in [
        (0, b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")),
        (1, b256!("94ac38107e10f8495dedf4621d9100d566bb376b8adb4850425a003b5cef479d")),
        (4, b256!("e288b5a499b31a13788b9d59b5cf9ef4e2d241f4c60b07e7521b0ec8501b1549")),
        (5, b256!("4d4084a6276735bdb0ef4b26f29423c7a084d84d9c6008b1c57262429097be39")),
        (6, b256!("7e893ad228751090c7bd8242f7c3abee7a4ae613a1b1d299b780f4a2bffa554d")),
        (21, b256!("a4c07072f7b1bf976ea730e94e0164c4f34b317db9e53566196d21cac9c173a3")),
        (22, b256!("cf70fb2685713fc946c67206cb9f8b77ea2e217bcad6eb0d479b8292c60a1ca4")),
    ] {
        let transactions = (0..count)
            .map(|nonce| {
                let mut payload = four_variants()[nonce % 4].payload().clone();
                payload.nonce = u64::try_from(nonce).unwrap();
                TransactionSsz::new(payload, signature()).unwrap()
            })
            .collect::<Vec<_>>();
        let snapshot = TransactionSnapshot::build(transactions.clone()).unwrap();
        assert_eq!(snapshot.root(), expected_root);
        let decoded = TransactionSnapshot::from_ssz(snapshot.serialized()).unwrap();
        assert_eq!(decoded.transactions(), transactions);
        assert_eq!(decoded.root(), snapshot.root());
        assert_eq!(snapshot.root(), snapshot.tree().root());
        assert!(snapshot.transaction_tree(count).is_none());
        assert!(snapshot.transaction_tree(usize::MAX).is_none());

        for (index, transaction) in transactions.iter().enumerate() {
            let singleton = TransactionSnapshot::build(vec![transaction.clone()]).unwrap();
            let node = snapshot.transaction_tree(index).unwrap();
            assert_eq!(node.root(), singleton.transaction_tree(0).unwrap().root());
            assert!(node.children().is_some());
        }

        if count > 1 {
            let mut reordered = transactions;
            reordered.reverse();
            assert_ne!(TransactionSnapshot::build(reordered).unwrap().root(), snapshot.root());
        }
    }
    assert_eq!(
        TransactionSnapshot::build(Vec::new()).unwrap().root(),
        b256!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    );
}

#[test]
fn mutations_change_the_retained_commitment() {
    let original = four_variants().remove(0);
    let root = TransactionSnapshot::build(vec![original.clone()]).unwrap().root();
    let mut payload = original.payload().clone();
    payload.input = Bytes::from(vec![0x01, 0x02, 0x04]);
    assert_ne!(
        TransactionSnapshot::build(vec![TransactionSsz::new(payload, signature()).unwrap()])
            .unwrap()
            .root(),
        root,
    );
    let changed =
        TransactionSsz::new(original.payload().clone(), signature().with_parity(false)).unwrap();
    assert_ne!(TransactionSnapshot::build(vec![changed]).unwrap().root(), root);
}

#[test]
fn malformed_transaction_encodings_are_rejected_without_panics() {
    for transaction in four_variants() {
        let bytes = encode_transaction(&transaction).unwrap();
        for length in 0..bytes.len() {
            assert!(decode_transaction(&bytes[..length]).is_err());
        }
        let fixed_length = match transaction.selector() {
            1 => 105,
            2 => 85,
            3 => 137,
            4 => 117,
            _ => unreachable!(),
        };
        let signature_offset = bytes.len() - 66;
        for (position, replacement) in [
            (0, 7),
            (4, 0),
            (8, 0),
            (8, 5),
            (9, 1),
            (9 + fixed_length - 4, 0),
            (signature_offset, 1),
            (bytes.len() - 1, 2),
        ] {
            let mut invalid = bytes.clone();
            invalid[position] = replacement;
            assert!(decode_transaction(&invalid).is_err());
        }
    }
}

#[test]
fn malformed_list_offsets_are_rejected() {
    let bytes = encode_transactions(&four_variants()).unwrap();
    for offset in [0_u32, 3, 20, u32::MAX] {
        let mut invalid = bytes.clone();
        invalid[..4].copy_from_slice(&offset.to_le_bytes());
        assert!(decode_transactions(&invalid).is_err());
    }
    let first = bytes[..4].to_vec();
    for offset in [0_u32, 16, u32::MAX] {
        let mut invalid = bytes.clone();
        invalid[4..8].copy_from_slice(&offset.to_le_bytes());
        assert!(decode_transactions(&invalid).is_err());
    }
    let mut overlapping = bytes;
    overlapping[4..8].copy_from_slice(&first);
    assert!(decode_transactions(&overlapping).is_err());
}

#[test]
fn invalid_signature_scalars_are_rejected() {
    let order = (SECP256K1N_HALF << 1) + U256::from(1);
    for signature in [
        Signature::new(U256::ZERO, U256::from(1), false),
        Signature::new(order, U256::from(1), false),
        Signature::new(U256::from(1), U256::ZERO, false),
        Signature::new(U256::from(1), SECP256K1N_HALF + U256::from(1), false),
    ] {
        assert!(matches!(
            TransactionSsz::new(four_variants()[0].payload().clone(), signature),
            Err(TransactionError::InvalidSignature),
        ));
    }
}

#[test]
fn full_width_values_survive_ssz_without_truncating_into_alloy() {
    for field in ["chain_id", "gas_price"] {
        let mut payload = four_variants()[2].payload().clone();
        if field == "chain_id" {
            payload.chain_id = Some(U256::MAX);
        } else {
            payload.gas_price = U256::MAX;
        }
        let transaction = TransactionSsz::new(payload, signature()).unwrap();
        let decoded = decode_transaction(&encode_transaction(&transaction).unwrap()).unwrap();
        assert_eq!(decoded, transaction);
        assert!(matches!(
            decoded.to_alloy(),
            Err(TransactionError::UnsupportedWidth(actual)) if actual == field,
        ));
    }
}

#[test]
fn source_conversion_rejects_nonlegacy_and_incorrect_cached_hashes() {
    let legacy = four_variants()[0].to_alloy().unwrap();
    let invalid_hash = Signed::new_unchecked(legacy.tx().clone(), *legacy.signature(), B256::ZERO);
    assert!(matches!(
        TransactionSsz::from_alloy(&invalid_hash),
        Err(TransactionError::SourceHashMismatch),
    ));

    let transactions = vec![
        EthereumTxEnvelope::Legacy(legacy),
        EthereumTxEnvelope::Eip1559(Signed::new_unhashed(TxEip1559::default(), signature())),
    ];
    assert!(matches!(
        convert_transactions(&transactions),
        Err(TransactionError::UnsupportedTransaction { index: 1 }),
    ));

    let mut rlp = four_variants()[0].original_rlp().unwrap().to_vec();
    rlp.push(0);
    assert!(matches!(TransactionSsz::from_rlp(&rlp), Err(TransactionError::TrailingBytes)));
}
