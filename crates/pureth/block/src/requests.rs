use crate::{active_container, uint64, BuilderDepositRequest, BuilderExitRequest};
use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use reth_pureth_ssz::{
    merkleize_fixed, merkleize_progressive, mix_in_length, RetainedNode, TreeConstructionError,
};
use ssz::{Decode, DecodeError, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use std::fmt;

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct DepositRequest {
    pub pubkey: FixedBytes<48>,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: FixedBytes<96>,
    pub index: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: FixedBytes<48>,
    pub amount: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: FixedBytes<48>,
    pub target_pubkey: FixedBytes<48>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
    pub builder_deposits: Vec<BuilderDepositRequest>,
    pub builder_exits: Vec<BuilderExitRequest>,
}

#[derive(Debug)]
pub enum RequestsError {
    LimitExceeded(&'static str),
    InvalidGroups(&'static str),
    UnsupportedType(u8),
    Decode(DecodeError),
    Tree(TreeConstructionError),
}

impl fmt::Display for RequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(name) => write!(f, "execution requests exceed {name} limit"),
            Self::InvalidGroups(reason) => write!(f, "invalid execution request groups: {reason}"),
            Self::UnsupportedType(tag) => write!(f, "unsupported execution request type: {tag}"),
            Self::Decode(error) => write!(f, "execution requests decoding failed: {error:?}"),
            Self::Tree(error) => write!(f, "execution requests tree failed: {error}"),
        }
    }
}

impl std::error::Error for RequestsError {}

impl From<TreeConstructionError> for RequestsError {
    fn from(error: TreeConstructionError) -> Self {
        Self::Tree(error)
    }
}

impl ExecutionRequests {
    pub fn from_native_groups(groups: &[Bytes]) -> Result<Self, RequestsError> {
        let mut requests = Self::default();
        let mut previous = None;
        for group in groups {
            let (&tag, body) =
                group.split_first().ok_or(RequestsError::InvalidGroups("empty group"))?;
            if tag > 4 {
                return Err(RequestsError::UnsupportedType(tag));
            }
            if previous.is_some_and(|previous| tag <= previous) {
                return Err(RequestsError::InvalidGroups("unordered or duplicate type"));
            }
            if body.is_empty() {
                return Err(RequestsError::InvalidGroups("empty request body"));
            }
            match tag {
                0 => {
                    requests.deposits =
                        decode_list(body, 192, usize::MAX).map_err(RequestsError::Decode)?
                }
                1 => {
                    requests.withdrawals =
                        decode_list(body, 76, 16).map_err(RequestsError::Decode)?
                }
                2 => {
                    requests.consolidations =
                        decode_list(body, 116, 2).map_err(RequestsError::Decode)?
                }
                3 => {
                    requests.builder_deposits =
                        decode_list(body, 184, 64).map_err(RequestsError::Decode)?
                }
                4 => {
                    requests.builder_exits =
                        decode_list(body, 68, 16).map_err(RequestsError::Decode)?
                }
                _ => unreachable!(),
            }
            previous = Some(tag);
        }
        Ok(requests)
    }

    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, RequestsError> {
        self.check_limits()?;
        let mut bytes = Vec::new();
        let mut encoder = SszEncoder::container(&mut bytes, 20);
        encoder.append(&self.deposits);
        encoder.append(&self.withdrawals);
        encoder.append(&self.consolidations);
        encoder.append(&self.builder_deposits);
        encoder.append(&self.builder_exits);
        encoder.finalize();
        Ok(bytes)
    }

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, RequestsError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        for _ in 0..5 {
            builder.register_type::<Vec<u8>>().map_err(RequestsError::Decode)?;
        }
        let mut decoder = builder.build().map_err(RequestsError::Decode)?;
        let requests = Self {
            deposits: decoder
                .decode_next_with(|bytes| decode_list::<DepositRequest>(bytes, 192, usize::MAX))
                .map_err(RequestsError::Decode)?,
            withdrawals: decoder
                .decode_next_with(|bytes| decode_list::<WithdrawalRequest>(bytes, 76, 16))
                .map_err(RequestsError::Decode)?,
            consolidations: decoder
                .decode_next_with(|bytes| decode_list::<ConsolidationRequest>(bytes, 116, 2))
                .map_err(RequestsError::Decode)?,
            builder_deposits: decoder
                .decode_next_with(|bytes| decode_list::<BuilderDepositRequest>(bytes, 184, 64))
                .map_err(RequestsError::Decode)?,
            builder_exits: decoder
                .decode_next_with(|bytes| decode_list::<BuilderExitRequest>(bytes, 68, 16))
                .map_err(RequestsError::Decode)?,
        };
        requests.check_limits()?;
        Ok(requests)
    }

    fn check_limits(&self) -> Result<(), RequestsError> {
        for (length, bound, name) in [
            (self.withdrawals.len(), 16, "withdrawals"),
            (self.consolidations.len(), 2, "consolidations"),
            (self.builder_deposits.len(), 64, "builder deposits"),
            (self.builder_exits.len(), 16, "builder exits"),
        ] {
            if length > bound {
                return Err(RequestsError::LimitExceeded(name));
            }
        }
        Ok(())
    }

    pub fn tree(&self) -> Result<RetainedNode, RequestsError> {
        self.check_limits()?;
        let deposits = self
            .deposits
            .iter()
            .map(|value| {
                merkleize_fixed(
                    vec![
                        bytes_tree(value.pubkey.as_slice())?,
                        RetainedNode::leaf(value.withdrawal_credentials),
                        uint64(value.amount),
                        bytes_tree(value.signature.as_slice())?,
                        uint64(value.index),
                    ],
                    8,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let withdrawals = self
            .withdrawals
            .iter()
            .map(|value| {
                merkleize_fixed(
                    vec![
                        bytes_tree(value.source_address.as_slice())?,
                        bytes_tree(value.validator_pubkey.as_slice())?,
                        uint64(value.amount),
                    ],
                    4,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let consolidations = self
            .consolidations
            .iter()
            .map(|value| {
                merkleize_fixed(
                    vec![
                        bytes_tree(value.source_address.as_slice())?,
                        bytes_tree(value.source_pubkey.as_slice())?,
                        bytes_tree(value.target_pubkey.as_slice())?,
                    ],
                    4,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let list = |nodes, length| {
            Ok::<_, TreeConstructionError>(mix_in_length(merkleize_progressive(nodes)?, length))
        };
        let mut fields = vec![
            list(deposits, self.deposits.len())?,
            list(withdrawals, self.withdrawals.len())?,
            list(consolidations, self.consolidations.len())?,
        ];
        let deposits = self
            .builder_deposits
            .iter()
            .map(|value| {
                merkleize_fixed(
                    vec![
                        bytes_tree(value.pubkey.as_slice())?,
                        RetainedNode::leaf(value.withdrawal_credentials),
                        uint64(value.amount),
                        bytes_tree(value.signature.as_slice())?,
                    ],
                    4,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let exits = self
            .builder_exits
            .iter()
            .map(|value| {
                merkleize_fixed(
                    vec![
                        bytes_tree(value.source_address.as_slice())?,
                        bytes_tree(value.pubkey.as_slice())?,
                    ],
                    2,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        fields.push(list(deposits, self.builder_deposits.len())?);
        fields.push(list(exits, self.builder_exits.len())?);
        Ok(active_container(fields, 0x1f)?)
    }
}

fn decode_list<T: Decode>(bytes: &[u8], width: usize, bound: usize) -> Result<Vec<T>, DecodeError> {
    if !bytes.len().is_multiple_of(width) || bytes.len() / width > bound {
        return Err(DecodeError::BytesInvalid("invalid execution request list length".into()));
    }
    Vec::<T>::from_ssz_bytes(bytes)
}

fn bytes_tree(bytes: &[u8]) -> Result<RetainedNode, TreeConstructionError> {
    let nodes =
        bytes.chunks(32).map(|bytes| RetainedNode::leaf(B256::right_padding_from(bytes))).collect();
    merkleize_fixed(nodes, bytes.len().div_ceil(32).next_power_of_two())
}

#[derive(Debug)]
pub struct ExecutionRequestsSnapshot {
    requests: ExecutionRequests,
    serialized: Bytes,
    tree: RetainedNode,
}

impl ExecutionRequestsSnapshot {
    pub fn from_native_groups(groups: &[Bytes]) -> Result<Self, RequestsError> {
        Self::build(ExecutionRequests::from_native_groups(groups)?)
    }
    pub fn build(requests: ExecutionRequests) -> Result<Self, RequestsError> {
        let serialized = Bytes::from(requests.to_ssz_bytes()?);
        let tree = requests.tree()?;
        Ok(Self { requests, serialized, tree })
    }
    pub fn from_ssz(bytes: &[u8]) -> Result<Self, RequestsError> {
        Self::build(ExecutionRequests::from_ssz_bytes(bytes)?)
    }
    pub const fn requests(&self) -> &ExecutionRequests {
        &self.requests
    }
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
    pub const fn tree(&self) -> &RetainedNode {
        &self.tree
    }
    pub const fn root(&self) -> B256 {
        self.tree.root()
    }
}

#[cfg(test)]
mod tests;
