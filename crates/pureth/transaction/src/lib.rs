#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

use alloy_consensus::{
    crypto::{RecoveryError, SECP256K1N_HALF},
    transaction::SignerRecoverable,
    EthereumTxEnvelope, Signed, TxEip4844, TxLegacy,
};
use alloy_primitives::{keccak256, Bytes, Signature, TxKind, B256, U256};
use std::fmt;

mod codec;
mod snapshot;

pub use codec::{decode_transaction, decode_transactions, encode_transaction, encode_transactions};
pub use snapshot::TransactionSnapshot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyPayload {
    pub chain_id: Option<U256>,
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub to: TxKind,
    pub value: U256,
    pub input: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSsz {
    payload: LegacyPayload,
    signature: Signature,
}

impl TransactionSsz {
    pub fn new(payload: LegacyPayload, signature: Signature) -> Result<Self, TransactionError> {
        validate_signature(&signature)?;
        Ok(Self { payload, signature })
    }

    pub fn from_alloy(signed: &Signed<TxLegacy>) -> Result<Self, TransactionError> {
        let TxLegacy { chain_id, nonce, gas_price, gas_limit, to, value, input } = signed.tx();
        let transaction = Self::new(
            LegacyPayload {
                chain_id: chain_id.map(U256::from),
                nonce: *nonce,
                gas_price: U256::from(*gas_price),
                gas_limit: *gas_limit,
                to: *to,
                value: *value,
                input: input.clone(),
            },
            *signed.signature(),
        )?;

        if transaction.to_alloy()?.hash() != signed.hash() {
            return Err(TransactionError::SourceHashMismatch);
        }

        Ok(transaction)
    }

    pub fn from_rlp(bytes: &[u8]) -> Result<Self, TransactionError> {
        let mut remaining = bytes;
        let signed =
            Signed::<TxLegacy>::rlp_decode(&mut remaining).map_err(TransactionError::Rlp)?;

        if !remaining.is_empty() {
            return Err(TransactionError::TrailingBytes);
        }

        let transaction = Self::from_alloy(&signed)?;
        if transaction.original_rlp()?.as_ref() != bytes {
            return Err(TransactionError::NonCanonicalRlp);
        }

        Ok(transaction)
    }

    pub fn to_alloy(&self) -> Result<Signed<TxLegacy>, TransactionError> {
        let chain_id = self
            .payload
            .chain_id
            .map(|value| {
                u64::try_from(value).map_err(|_| TransactionError::UnsupportedWidth("chain_id"))
            })
            .transpose()?;
        let gas_price = u128::try_from(self.payload.gas_price)
            .map_err(|_| TransactionError::UnsupportedWidth("gas_price"))?;

        let signed = Signed::new_unhashed(
            TxLegacy {
                chain_id,
                nonce: self.payload.nonce,
                gas_price,
                gas_limit: self.payload.gas_limit,
                to: self.payload.to,
                value: self.payload.value,
                input: self.payload.input.clone(),
            },
            self.signature,
        );
        SignerRecoverable::recover_signer(&signed).map_err(TransactionError::Recovery)?;

        Ok(signed)
    }

    pub const fn payload(&self) -> &LegacyPayload {
        &self.payload
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub const fn selector(&self) -> u8 {
        match (self.payload.chain_id.is_some(), self.payload.to) {
            (false, TxKind::Call(_)) => 0x01,
            (false, TxKind::Create) => 0x02,
            (true, TxKind::Call(_)) => 0x03,
            (true, TxKind::Create) => 0x04,
        }
    }

    pub fn original_rlp(&self) -> Result<Bytes, TransactionError> {
        let signed = self.to_alloy()?;
        let mut bytes = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut bytes);
        Ok(Bytes::from(bytes))
    }

    pub fn original_transaction_hash(&self) -> Result<B256, TransactionError> {
        Ok(keccak256(self.original_rlp()?))
    }

    pub fn original_signing_hash(&self) -> Result<B256, TransactionError> {
        Ok(self.to_alloy()?.signature_hash())
    }
}

pub fn convert_transactions(
    transactions: &[EthereumTxEnvelope<TxEip4844>],
) -> Result<Vec<TransactionSsz>, TransactionError> {
    transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| match transaction {
            EthereumTxEnvelope::Legacy(signed) => TransactionSsz::from_alloy(signed),
            _ => Err(TransactionError::UnsupportedTransaction { index }),
        })
        .collect()
}

#[derive(Debug)]
pub enum TransactionError {
    InvalidSignature,
    InvalidEncoding(&'static str),
    LengthOverflow,
    UnsupportedSelector(u8),
    UnsupportedWidth(&'static str),
    UnsupportedTransaction { index: usize },
    SourceHashMismatch,
    NonCanonicalRlp,
    TrailingBytes,
    Rlp(alloy_rlp::Error),
    Recovery(RecoveryError),
    Tree(reth_pureth_ssz::TreeConstructionError),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => formatter.write_str("invalid transaction signature"),
            Self::InvalidEncoding(reason) => {
                write!(formatter, "invalid transaction SSZ: {reason}")
            }
            Self::LengthOverflow => formatter.write_str("transaction encoding length overflow"),
            Self::UnsupportedSelector(selector) => {
                write!(formatter, "unsupported transaction selector {selector}")
            }
            Self::UnsupportedWidth(field) => {
                write!(formatter, "{field} exceeds the supported Alloy execution width")
            }
            Self::UnsupportedTransaction { index } => {
                write!(formatter, "unsupported non-legacy transaction at index {index}")
            }
            Self::SourceHashMismatch => formatter.write_str("source transaction hash mismatch"),
            Self::NonCanonicalRlp => formatter.write_str("non-canonical legacy RLP"),
            Self::TrailingBytes => formatter.write_str("trailing legacy RLP bytes"),
            Self::Rlp(error) => write!(formatter, "legacy RLP decoding failed: {error}"),
            Self::Recovery(error) => {
                write!(formatter, "transaction signer recovery failed: {error}")
            }
            Self::Tree(error) => write!(formatter, "transaction tree construction failed: {error}"),
        }
    }
}

impl std::error::Error for TransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rlp(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Tree(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_signature(signature: &Signature) -> Result<(), TransactionError> {
    let order = (SECP256K1N_HALF << 1) + U256::from(1);

    if signature.r() == U256::ZERO ||
        signature.r() >= order ||
        signature.s() == U256::ZERO ||
        signature.s() > SECP256K1N_HALF
    {
        return Err(TransactionError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
