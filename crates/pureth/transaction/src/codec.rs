use crate::{LegacyPayload, TransactionError, TransactionSsz};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};

pub fn encode_transaction(transaction: &TransactionSsz) -> Result<Vec<u8>, TransactionError> {
    let payload = transaction.payload();
    let fixed_length = payload_fixed_length(transaction.selector())?;
    let payload_length = 1_usize
        .checked_add(fixed_length)
        .and_then(|length| length.checked_add(payload.input.len()))
        .ok_or(TransactionError::LengthOverflow)?;
    let signature_offset =
        8_usize.checked_add(payload_length).ok_or(TransactionError::LengthOverflow)?;
    let total_length = signature_offset.checked_add(66).ok_or(TransactionError::LengthOverflow)?;
    checked_offset(total_length)?;

    let mut bytes = Vec::with_capacity(total_length);
    append_offset(&mut bytes, 8)?;
    append_offset(&mut bytes, signature_offset)?;
    bytes.push(transaction.selector());
    bytes.push(0);

    if let Some(chain_id) = payload.chain_id {
        bytes.extend_from_slice(&chain_id.to_le_bytes::<32>());
    }

    bytes.extend_from_slice(&payload.nonce.to_le_bytes());
    bytes.extend_from_slice(&payload.gas_price.to_le_bytes::<32>());
    bytes.extend_from_slice(&payload.gas_limit.to_le_bytes());

    if let TxKind::Call(address) = payload.to {
        bytes.extend_from_slice(address.as_slice());
    }

    bytes.extend_from_slice(&payload.value.to_le_bytes::<32>());
    append_offset(&mut bytes, fixed_length)?;
    bytes.extend_from_slice(payload.input.as_ref());
    bytes.extend_from_slice(&signature_bytes(transaction.signature()));

    Ok(bytes)
}

pub fn decode_transaction(bytes: &[u8]) -> Result<TransactionSsz, TransactionError> {
    checked_offset(bytes.len())?;

    if bytes.len() < 8 {
        return Err(TransactionError::InvalidEncoding("missing container offsets"));
    }
    if read_offset(bytes, 0)? != 8 {
        return Err(TransactionError::InvalidEncoding("non-canonical payload offset"));
    }

    let signature_offset = read_offset(bytes, 4)?;
    if signature_offset < 9 ||
        signature_offset > bytes.len() ||
        bytes.len() - signature_offset != 66
    {
        return Err(TransactionError::InvalidEncoding("invalid signature offset or length"));
    }

    let selector = bytes[8];
    let fixed_length = payload_fixed_length(selector)?;
    let payload_bytes = &bytes[9..signature_offset];
    if payload_bytes.len() < fixed_length {
        return Err(TransactionError::InvalidEncoding("truncated payload"));
    }

    let mut cursor = 0;
    if take::<1>(payload_bytes, &mut cursor)?[0] != 0 {
        return Err(TransactionError::InvalidEncoding("legacy transaction type must be zero"));
    }

    let chain_id = if matches!(selector, 0x03 | 0x04) {
        Some(U256::from_le_bytes(take::<32>(payload_bytes, &mut cursor)?))
    } else {
        None
    };
    let nonce = u64::from_le_bytes(take::<8>(payload_bytes, &mut cursor)?);
    let gas_price = U256::from_le_bytes(take::<32>(payload_bytes, &mut cursor)?);
    let gas_limit = u64::from_le_bytes(take::<8>(payload_bytes, &mut cursor)?);
    let to = if matches!(selector, 0x01 | 0x03) {
        TxKind::Call(Address::from(take::<20>(payload_bytes, &mut cursor)?))
    } else {
        TxKind::Create
    };
    let value = U256::from_le_bytes(take::<32>(payload_bytes, &mut cursor)?);
    let input_offset = u32::from_le_bytes(take::<4>(payload_bytes, &mut cursor)?) as usize;

    if cursor != fixed_length || input_offset != fixed_length {
        return Err(TransactionError::InvalidEncoding("non-canonical input offset"));
    }

    let signature_bytes = &bytes[signature_offset..];
    if signature_bytes[0] != 0 || signature_bytes[65] > 1 {
        return Err(TransactionError::InvalidSignature);
    }

    let signature = Signature::new(
        U256::from_be_slice(&signature_bytes[1..33]),
        U256::from_be_slice(&signature_bytes[33..65]),
        signature_bytes[65] == 1,
    );

    TransactionSsz::new(
        LegacyPayload {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            input: Bytes::copy_from_slice(&payload_bytes[fixed_length..]),
        },
        signature,
    )
}

pub fn encode_transactions(transactions: &[TransactionSsz]) -> Result<Vec<u8>, TransactionError> {
    let fixed_length = transactions.len().checked_mul(4).ok_or(TransactionError::LengthOverflow)?;
    checked_offset(fixed_length)?;
    let encoded = transactions.iter().map(encode_transaction).collect::<Result<Vec<_>, _>>()?;
    let total_length = encoded.iter().try_fold(fixed_length, |length, bytes| {
        length.checked_add(bytes.len()).ok_or(TransactionError::LengthOverflow)
    })?;
    checked_offset(total_length)?;

    let mut bytes = Vec::with_capacity(total_length);
    let mut offset = fixed_length;
    for transaction in &encoded {
        append_offset(&mut bytes, offset)?;
        offset = offset.checked_add(transaction.len()).ok_or(TransactionError::LengthOverflow)?;
    }
    for transaction in encoded {
        bytes.extend_from_slice(&transaction);
    }

    Ok(bytes)
}

pub fn decode_transactions(bytes: &[u8]) -> Result<Vec<TransactionSsz>, TransactionError> {
    checked_offset(bytes.len())?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let fixed_length = read_offset(bytes, 0)?;
    if fixed_length == 0 || !fixed_length.is_multiple_of(4) || fixed_length > bytes.len() {
        return Err(TransactionError::InvalidEncoding("invalid transaction-list offset table"));
    }

    let count = fixed_length / 4;
    let mut transactions = Vec::with_capacity(count);
    for index in 0..count {
        let start = read_offset(bytes, index * 4)?;
        let end =
            if index + 1 == count { bytes.len() } else { read_offset(bytes, (index + 1) * 4)? };

        if start < fixed_length || end <= start || end > bytes.len() {
            return Err(TransactionError::InvalidEncoding(
                "invalid transaction-list element offsets",
            ));
        }
        transactions.push(decode_transaction(&bytes[start..end])?);
    }

    Ok(transactions)
}

pub(crate) fn signature_bytes(signature: &Signature) -> [u8; 66] {
    let mut bytes = [0_u8; 66];
    bytes[1..33].copy_from_slice(&signature.r().to_be_bytes::<32>());
    bytes[33..65].copy_from_slice(&signature.s().to_be_bytes::<32>());
    bytes[65] = u8::from(signature.v());
    bytes
}

const fn payload_fixed_length(selector: u8) -> Result<usize, TransactionError> {
    match selector {
        0x01 => Ok(105),
        0x02 => Ok(85),
        0x03 => Ok(137),
        0x04 => Ok(117),
        _ => Err(TransactionError::UnsupportedSelector(selector)),
    }
}

fn checked_offset(value: usize) -> Result<u32, TransactionError> {
    u32::try_from(value).map_err(|_| TransactionError::LengthOverflow)
}

fn append_offset(bytes: &mut Vec<u8>, offset: usize) -> Result<(), TransactionError> {
    bytes.extend_from_slice(&checked_offset(offset)?.to_le_bytes());
    Ok(())
}

fn read_offset(bytes: &[u8], position: usize) -> Result<usize, TransactionError> {
    let mut cursor = position;
    Ok(u32::from_le_bytes(take::<4>(bytes, &mut cursor)?) as usize)
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], TransactionError> {
    let end = cursor.checked_add(N).ok_or(TransactionError::LengthOverflow)?;
    let value =
        bytes.get(*cursor..end).ok_or(TransactionError::InvalidEncoding("truncated field"))?;
    let mut result = [0_u8; N];
    result.copy_from_slice(value);
    *cursor = end;
    Ok(result)
}
