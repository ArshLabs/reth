use crate::{
    codec::signature_bytes, decode_transactions, encode_transactions, LegacyPayload,
    TransactionError, TransactionSsz,
};
use alloy_primitives::{Bytes, TxKind, B256, U256};
use reth_pureth_ssz::{merkleize_progressive, mix_in_length, progressive_byte_list, RetainedNode};

#[derive(Debug)]
pub struct TransactionSnapshot {
    transactions: Vec<TransactionSsz>,
    serialized: Bytes,
    tree: RetainedNode,
}

impl TransactionSnapshot {
    pub fn build(transactions: Vec<TransactionSsz>) -> Result<Self, TransactionError> {
        let serialized = Bytes::from(encode_transactions(&transactions)?);
        let nodes = transactions.iter().map(transaction_tree).collect::<Result<Vec<_>, _>>()?;
        let contents = merkleize_progressive(nodes).map_err(TransactionError::Tree)?;
        let tree = mix_in_length(contents, transactions.len());
        Ok(Self { transactions, serialized, tree })
    }

    pub fn from_ssz(bytes: &[u8]) -> Result<Self, TransactionError> {
        Self::build(decode_transactions(bytes)?)
    }

    pub fn transactions(&self) -> &[TransactionSsz] {
        &self.transactions
    }

    pub fn serialized(&self) -> &[u8] {
        self.serialized.as_ref()
    }

    pub const fn tree(&self) -> &RetainedNode {
        &self.tree
    }

    pub const fn root(&self) -> B256 {
        self.tree.root()
    }

    pub fn transaction_tree(&self, index: usize) -> Option<&RetainedNode> {
        self.transactions.get(index)?;
        let contents = &self.tree.children()?[0];
        progressive_element(contents, index, 1)
    }
}

fn transaction_tree(transaction: &TransactionSsz) -> Result<RetainedNode, TransactionError> {
    let LegacyPayload { chain_id, nonce, gas_price, gas_limit, to, value, input } =
        transaction.payload();
    let fees =
        merkleize_progressive(vec![uint256_node(*gas_price)]).map_err(TransactionError::Tree)?;
    let fees = RetainedNode::pair(fees, word_node(1));
    let destination = match to {
        TxKind::Call(address) => {
            let mut bytes = [0_u8; 32];
            bytes[..20].copy_from_slice(address.as_slice());
            RetainedNode::leaf(B256::from(bytes))
        }
        TxKind::Create => RetainedNode::zero(),
    };

    let fields = vec![
        word_node(0),
        chain_id.map_or_else(RetainedNode::zero, uint256_node),
        word_node(*nonce),
        fees,
        word_node(*gas_limit),
        destination,
        uint256_node(*value),
        progressive_byte_list(input.as_ref()).map_err(TransactionError::Tree)?,
    ];
    let active_fields = match transaction.selector() {
        0x01 => 0xfd,
        0x02 => 0xdd,
        0x03 => 0xff,
        0x04 => 0xdf,
        selector => return Err(TransactionError::UnsupportedSelector(selector)),
    };
    let payload = RetainedNode::pair(
        merkleize_progressive(fields).map_err(TransactionError::Tree)?,
        word_node(active_fields),
    );
    let payload = RetainedNode::pair(payload, word_node(u64::from(transaction.selector())));
    let signature = progressive_byte_list(&signature_bytes(transaction.signature()))
        .map_err(TransactionError::Tree)?;
    Ok(RetainedNode::pair(payload, signature))
}

fn uint256_node(value: U256) -> RetainedNode {
    RetainedNode::leaf(B256::from(value.to_le_bytes::<32>()))
}

fn word_node(value: u64) -> RetainedNode {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    RetainedNode::leaf(B256::from(bytes))
}

fn progressive_element(node: &RetainedNode, index: usize, width: usize) -> Option<&RetainedNode> {
    let children = node.children()?;
    if index < width {
        return fixed_element(&children[0], index, width);
    }
    progressive_element(&children[1], index.checked_sub(width)?, width.checked_mul(4)?)
}

fn fixed_element(node: &RetainedNode, index: usize, width: usize) -> Option<&RetainedNode> {
    if width == 1 {
        return Some(node);
    }
    let children = node.children()?;
    let half = width / 2;
    if index < half {
        fixed_element(&children[0], index, half)
    } else {
        fixed_element(&children[1], index - half, half)
    }
}
