//! Captured source acquisition over the existing canonical provider and retained block graph.

use crate::{received_source, ExecutionEngineValidator};
use alloy_consensus::BlockHeader;
use alloy_eip7928::bal::Bal;
use alloy_eips::{eip2718::Encodable2718, BlockId, BlockNumberOrTag};
use alloy_primitives::{Sealable, B256};
use alloy_rlp::Decodable;
use parking_lot::{Mutex, MutexGuard};
use pureth_withdrawal_root::WithdrawalSnapshot;
use reth_chain_state::ExecutedBlock;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks, Hardforks};
use reth_primitives_traits::{BlockBody, SealedHeader};
use reth_provider::{
    providers::{BlockchainProvider, ConsistentProvider, ProviderNodeTypes},
    BalProvider, BlockBodyIndicesProvider, BlockHashReader, BlockNumReader, BlockReader,
    HeaderProvider, ProviderError, ReceiptProvider, TransactionVariant, TransactionsProvider,
};
use reth_pureth_block::{
    BlockAccessListSnapshot, ExecutionHeader, ExecutionPrimitives, ExecutionQueryObject,
    ExecutionQuerySource, ExecutionRequestsSnapshot, ExecutionSource, ExecutionSourceProvider,
    ExecutionSummarySnapshot, PayloadError, PayloadSourceError, PayloadSourceInput,
    PayloadSourceKind, PayloadSourceMetadata,
};
use reth_pureth_receipt::{CanonicalityStatus, RootContext};
use reth_pureth_transaction::{convert_transactions, TransactionSnapshot};
use schnellru::{ByLength, LruMap};
use std::{
    borrow::Cow,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// Shares retained sources and checked historical readback. The entry limit bounds cache
/// residency, not source allocation, provider I/O, active consumers or process RSS.
#[derive(Debug)]
pub struct ExecutionSourceBackend<N: ProviderNodeTypes> {
    provider: BlockchainProvider<N>,
    validator: ExecutionEngineValidator,
    sources: Mutex<LruMap<B256, Arc<SourceEntry>, ByLength>>,
}

impl<N> ExecutionSourceBackend<N>
where
    N: ProviderNodeTypes<Primitives = ExecutionPrimitives>,
    N::ChainSpec: EthereumHardforks + Hardforks,
{
    /// Uses an explicit retention policy and the same validated activation configuration as
    /// builder/receiver integration. No production retention budget is inferred here.
    pub fn new(
        provider: BlockchainProvider<N>,
        validator: ExecutionEngineValidator,
        retained_entries: NonZeroU32,
    ) -> Result<Self, PayloadSourceError> {
        validator.validate_chain_spec(provider.chain_spec().as_ref())?;
        Ok(Self {
            provider,
            validator,
            sources: Mutex::new(LruMap::new(ByLength::new(retained_entries.get()))),
        })
    }

    fn capture(
        &self,
        selector: BlockId,
        cancelled: &AtomicBool,
    ) -> Result<CapturedSource<N>, PayloadSourceError> {
        check_cancelled(cancelled)?;
        let memory = self.provider.canonical_in_memory_state();
        // Moving markers are captured once, then checked against the canonical view below.
        let pending = matches!(selector, BlockId::Number(BlockNumberOrTag::Pending))
            .then(|| memory.pending_state())
            .flatten();
        let captured_head = memory.get_canonical_head();
        let marker = match selector {
            BlockId::Number(BlockNumberOrTag::Safe) => memory.get_safe_num_hash(),
            BlockId::Number(BlockNumberOrTag::Finalized) => memory.get_finalized_num_hash(),
            _ => None,
        };
        let view = self
            .provider
            .consistent_provider()
            .map_err(|error| read_error(PayloadSourceInput::ConsistentView, error))?;
        let head = captured_head.number();
        let canonical_hash = |number| {
            if number > head {
                return Ok(None);
            }
            view.block_hash(number)
                .map_err(|error| read_error(PayloadSourceInput::CanonicalHash, error))
        };
        if canonical_hash(head)? != Some(captured_head.hash()) {
            return Err(PayloadSourceError::SourceMismatch);
        }
        let hash = match selector {
            BlockId::Hash(hash) => hash.block_hash,
            BlockId::Number(BlockNumberOrTag::Pending) => {
                let pending = pending
                    .as_ref()
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?;
                if pending.number() != head.saturating_add(1) ||
                    Some(pending.block_ref().recovered_block().parent_hash()) !=
                        canonical_hash(head)?
                {
                    return Err(PayloadSourceError::SourceMismatch);
                }
                pending.hash()
            }
            BlockId::Number(BlockNumberOrTag::Safe | BlockNumberOrTag::Finalized) => {
                let marker =
                    marker.ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?;
                if marker.number > head || canonical_hash(marker.number)? != Some(marker.hash) {
                    return Err(PayloadSourceError::SourceMismatch);
                }
                marker.hash
            }
            BlockId::Number(number) => {
                let number = match number {
                    BlockNumberOrTag::Number(number) => number,
                    BlockNumberOrTag::Latest => head,
                    BlockNumberOrTag::Earliest => view
                        .earliest_block_number()
                        .map_err(|error| read_error(PayloadSourceInput::Block, error))?,
                    _ => unreachable!("moving markers handled above"),
                };
                canonical_hash(number)?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?
            }
        };
        check_cancelled(cancelled)?;
        let entry = self.sources.lock().peek(&hash).cloned();
        let executed = match pending {
            Some(state) => Some(state.block()),
            None => view
                .executed_block_by_hash(hash)
                .map_err(|error| read_error(PayloadSourceInput::Block, error))?
                .or_else(|| self.provider.retained_executed_block(hash)),
        };
        let cached = entry.as_ref().and_then(|entry| entry.receipts.try_lock()?.clone());
        let header = if let Some(executed) = &executed {
            executed.recovered_block.sealed_header().clone()
        } else if let Some(source) = &cached {
            source.block().sealed_header().clone()
        } else {
            view.sealed_header_by_hash(hash)
                .map_err(|error| read_error(PayloadSourceInput::Block, error))?
                .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?
        };
        if header.hash() != hash ||
            header.header().hash_slow() != hash ||
            header.is_ssz() !=
                self.validator.fork_config().is_active_at_timestamp(header.timestamp())
        {
            return Err(PayloadSourceError::SourceMismatch);
        }
        let identity = header.num_hash();
        let canonicality = match canonical_hash(header.number())? {
            Some(expected) if expected == hash && header.number() <= head => {
                CanonicalityStatus::Canonical
            }
            Some(_) => CanonicalityStatus::NonCanonical,
            None if header.number() > head => CanonicalityStatus::NonCanonical,
            None => CanonicalityStatus::Unknown,
        };
        if matches!(selector, BlockId::Hash(hash) if hash.require_canonical == Some(true)) &&
            canonicality != CanonicalityStatus::Canonical
        {
            return Err(PayloadSourceError::NonCanonicalBlock(identity));
        }
        if canonicality == CanonicalityStatus::Canonical &&
            header.number() > 0 &&
            canonical_hash(header.number() - 1)? != Some(header.parent_hash())
        {
            return Err(PayloadSourceError::SourceMismatch);
        }
        check_cancelled(cancelled)?;
        Ok(CapturedSource {
            view,
            executed,
            entry,
            header,
            metadata: PayloadSourceMetadata {
                native_block: identity,
                source_kind: PayloadSourceKind::Historical,
                canonicality,
                root_context: RootContext::RethExperimentalUnanchored,
            },
        })
    }

    fn acquire(
        &self,
        selector: BlockId,
        full: bool,
        cancelled: &AtomicBool,
    ) -> Result<Arc<ExecutionSource>, PayloadSourceError> {
        let CapturedSource { view, executed, entry, header, metadata } =
            self.capture(selector, cancelled)?;
        let identity = metadata.native_block;
        let hash = identity.hash;
        let canonicality = metadata.canonicality;
        let retained = executed.as_ref().map(received_source).transpose();
        let retained = match retained {
            Ok(source) => source,
            Err(PayloadSourceError::MissingInput(_)) => None,
            Err(error) => return Err(error),
        };
        let cached = entry.as_ref().and_then(|entry| entry.receipts.try_lock()?.clone());
        let block = if let Some(executed) = &executed {
            executed.recovered_block.clone()
        } else if let Some(source) = &cached {
            source.block_arc().clone()
        } else {
            Arc::new(
                view.recovered_block(hash.into(), TransactionVariant::WithHash)
                    .map_err(|error| read_error(PayloadSourceInput::Block, error))?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?,
            )
        };
        if block.num_hash() != identity || block.header() != header.header() {
            return Err(PayloadSourceError::SourceMismatch);
        }
        let cached_full = entry.as_ref().and_then(|entry| entry.payload.try_lock()?.clone());
        if let Some(source) = retained
            .as_ref()
            .filter(|source| !full || source.payload().is_ok())
            .or(cached_full.as_ref())
            .or_else(|| cached.as_ref().filter(|_| !full))
        {
            drop(view);
            check_cancelled(cancelled)?;
            let _ = self.sources.lock().get(&hash);
            return Ok(Arc::new(source.with_canonicality(canonicality)));
        }
        let receipts = if let Some(source) = retained.as_ref().or(cached.as_ref()) {
            source.native_receipts_arc().clone()
        } else if let Some(executed) = &executed {
            Arc::new(executed.execution_outcome().result.receipts.clone())
        } else {
            Arc::new(
                view.receipts_by_block(hash.into())
                    .map_err(|error| read_error(PayloadSourceInput::Receipts, error))?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Receipts))?,
            )
        };
        let requests = if full {
            // A live full source returned above already owns its real requests. Without that
            // attachment, require actual durable bodies: disk-to-memory execution outcomes may
            // substitute default empty requests for missing historical inputs.
            Some(
                view.execution_requests(identity)
                    .map_err(|error| read_error(PayloadSourceInput::Requests, error))?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Requests))?,
            )
        } else {
            None
        };
        let raw_bal = full
            .then(|| {
                executed.as_ref().and_then(|block| block.bal().map(|bal| bal.as_raw().clone()))
            })
            .flatten();
        // Copy/pin native inputs, then release the DB transaction before hashing or waiting.
        drop(view);
        check_cancelled(cancelled)?;
        let entry = self
            .sources
            .lock()
            .get_or_insert(hash, || entry.unwrap_or_else(|| Arc::new(SourceEntry::default())))
            .expect("nonzero cache capacity")
            .clone();
        let receipt_source = {
            let mut slot = lock_cancelled(&entry.receipts, cancelled)?;
            if slot.is_none() {
                let source = if let Some(source) = retained {
                    source
                } else {
                    Arc::new(ExecutionSource::from_receipts(
                        block,
                        receipts,
                        PayloadSourceMetadata {
                            native_block: identity,
                            source_kind: PayloadSourceKind::Historical,
                            canonicality: CanonicalityStatus::Unknown,
                            root_context: RootContext::RethExperimentalUnanchored,
                        },
                        self.validator.chain_spec().as_ref(),
                        &self.validator.fork_config(),
                        cancelled,
                    )?)
                };
                *slot = Some(source);
            }
            slot.as_ref().expect("initialized above").clone()
        };
        if !full {
            return Ok(Arc::new(receipt_source.with_canonicality(canonicality)));
        }
        let mut slot = lock_cancelled(&entry.payload, cancelled)?;
        if slot.is_none() {
            check_cancelled(cancelled)?;
            let raw = if let Some(raw) = raw_bal {
                raw
            } else {
                self.provider
                    .bal_store()
                    .get_by_hash(hash)
                    .map_err(|error| read_error(PayloadSourceInput::BlockAccessList, error))?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::BlockAccessList))?
            };
            if raw.len() > self.validator.limits().bal_bytes {
                return Err(PayloadSourceError::LimitExceeded);
            }
            let mut input = raw.as_ref();
            let bal = Bal::decode(&mut input).map_err(PayloadSourceError::BalDecode)?;
            if !input.is_empty() || alloy_rlp::encode(&bal).as_slice() != raw.as_ref() {
                return Err(PayloadSourceError::NonCanonicalBal);
            }
            let source = receipt_source.with_payload(
                requests.as_ref().expect("full acquisition"),
                &bal,
                self.validator.chain_spec().as_ref(),
                &self.validator.fork_config(),
                self.validator.limits(),
                cancelled,
            )?;
            *slot = Some(Arc::new(source));
        }
        check_cancelled(cancelled)?;
        Ok(Arc::new(slot.as_ref().expect("initialized above").with_canonicality(canonicality)))
    }
}

impl<N> ExecutionSourceProvider for ExecutionSourceBackend<N>
where
    N: ProviderNodeTypes<Primitives = ExecutionPrimitives>,
    N::ChainSpec: EthereumHardforks + Hardforks,
{
    fn receipt_source(
        &self,
        block: BlockId,
        cancelled: &AtomicBool,
    ) -> Result<Arc<ExecutionSource>, PayloadSourceError> {
        self.acquire(block, false, cancelled)
    }

    fn payload_source(
        &self,
        block: BlockId,
        cancelled: &AtomicBool,
    ) -> Result<Arc<ExecutionSource>, PayloadSourceError> {
        self.acquire(block, true, cancelled)
    }

    fn query_source(
        &self,
        object: ExecutionQueryObject,
        selector: BlockId,
        cancelled: &AtomicBool,
    ) -> Result<ExecutionQuerySource, PayloadSourceError> {
        if object == ExecutionQueryObject::ExecutionPayload {
            return self.payload_source(selector, cancelled).map(ExecutionQuerySource::Retained);
        }
        let CapturedSource { view, executed, entry, header, metadata } =
            self.capture(selector, cancelled)?;
        let retained = executed.as_ref().map(received_source).transpose();
        let retained = match retained {
            Ok(source) => source,
            Err(PayloadSourceError::MissingInput(_)) => None,
            Err(error) => return Err(error),
        };
        let cached = entry.as_ref().and_then(|entry| entry.payload.try_lock()?.clone());
        if let Some(source) =
            retained.as_ref().filter(|source| source.payload().is_ok()).or(cached.as_ref())
        {
            drop(view);
            check_cancelled(cancelled)?;
            return Ok(ExecutionQuerySource::Retained(Arc::new(
                source.with_canonicality(metadata.canonicality),
            )));
        }
        let summary = header.summary_ssz().ok_or(PayloadSourceError::UnsupportedFork)?;
        if summary.len() > self.validator.limits().bytes {
            return Err(PayloadSourceError::LimitExceeded);
        }
        let summary = ExecutionSummarySnapshot::from_ssz(summary)
            .map_err(|error| PayloadSourceError::Payload(PayloadError::Summary(error)))?;
        if summary.root() != metadata.native_block.hash {
            return Err(PayloadSourceError::SourceMismatch);
        }
        match object {
            ExecutionQueryObject::ExecutionSummary => {
                drop(view);
                check_cancelled(cancelled)?;
                Ok(ExecutionQuerySource::ExecutionSummary { snapshot: Box::new(summary), metadata })
            }
            ExecutionQueryObject::Transactions | ExecutionQueryObject::Withdrawals => {
                let cached = entry.as_ref().and_then(|entry| entry.receipts.try_lock()?.clone());
                let block = executed
                    .map(|executed| executed.recovered_block)
                    .or_else(|| cached.map(|source| source.block_arc().clone()));
                if block.as_ref().is_some_and(|block| {
                    block.num_hash() != metadata.native_block ||
                        block.header() != header.header() ||
                        !block.body().is_ssz()
                }) {
                    return Err(PayloadSourceError::SourceMismatch);
                }
                if object == ExecutionQueryObject::Transactions {
                    let limits =
                        self.validator.limits().for_amsterdam_gas_limit(header.gas_limit());
                    let count = if let Some(block) = &block {
                        block.transaction_count()
                    } else {
                        let indices = view
                            .block_body_indices(header.number())
                            .map_err(|error| read_error(PayloadSourceInput::Block, error))?
                            .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Block))?;
                        usize::try_from(indices.tx_count())
                            .map_err(|_| PayloadSourceError::LimitExceeded)?
                    };
                    if count > limits.transactions {
                        return Err(PayloadSourceError::LimitExceeded);
                    }
                    let transactions = if let Some(block) = &block {
                        Cow::Borrowed(block.body().transactions())
                    } else {
                        Cow::Owned(
                            view.transactions_by_block(metadata.native_block.hash.into())
                                .map_err(|error| read_error(PayloadSourceInput::Block, error))?
                                .ok_or(PayloadSourceError::MissingInput(
                                    PayloadSourceInput::Block,
                                ))?,
                        )
                    };
                    drop(view);
                    check_cancelled(cancelled)?;
                    if transactions.len() != count {
                        return Err(PayloadSourceError::SourceMismatch);
                    }
                    let mut size = 0usize;
                    for transaction in transactions.iter() {
                        check_cancelled(cancelled)?;
                        size = size
                            .checked_add(transaction.encode_2718_len())
                            .filter(|size| *size <= limits.bytes)
                            .ok_or(PayloadSourceError::LimitExceeded)?;
                    }
                    let snapshot = TransactionSnapshot::build(
                        convert_transactions(transactions.as_ref())
                            .map_err(PayloadSourceError::Transactions)?,
                    )
                    .map_err(PayloadSourceError::Transactions)?;
                    if snapshot.root() != summary.summary().transactions_root {
                        return Err(PayloadSourceError::SourceMismatch);
                    }
                    check_cancelled(cancelled)?;
                    Ok(ExecutionQuerySource::Transactions { snapshot, metadata })
                } else {
                    let withdrawals = if let Some(block) = &block {
                        Cow::Borrowed(
                            block
                                .body()
                                .withdrawals()
                                .ok_or(PayloadSourceError::MissingInput(
                                    PayloadSourceInput::Withdrawals,
                                ))?
                                .as_slice(),
                        )
                    } else {
                        Cow::Owned(
                            view.withdrawals_by_block(metadata.native_block)
                                .map_err(|error| {
                                    read_error(PayloadSourceInput::Withdrawals, error)
                                })?
                                .ok_or(PayloadSourceError::MissingInput(
                                    PayloadSourceInput::Withdrawals,
                                ))?
                                .into_inner(),
                        )
                    };
                    drop(view);
                    check_cancelled(cancelled)?;
                    if withdrawals.len() > self.validator.limits().withdrawals ||
                        withdrawals
                            .len()
                            .checked_mul(44)
                            .is_none_or(|size| size > self.validator.limits().bytes)
                    {
                        return Err(PayloadSourceError::LimitExceeded);
                    }
                    let snapshot = WithdrawalSnapshot::build(withdrawals.into_owned())
                        .map_err(PayloadSourceError::Withdrawals)?;
                    if snapshot.root() != summary.summary().withdrawals_root {
                        return Err(PayloadSourceError::SourceMismatch);
                    }
                    check_cancelled(cancelled)?;
                    Ok(ExecutionQuerySource::Withdrawals { snapshot, metadata })
                }
            }
            ExecutionQueryObject::ExecutionRequests => {
                let requests = view
                    .execution_requests(metadata.native_block)
                    .map_err(|error| read_error(PayloadSourceInput::Requests, error))?
                    .ok_or(PayloadSourceError::MissingInput(PayloadSourceInput::Requests))?;
                drop(view);
                check_cancelled(cancelled)?;
                let mut size = 0usize;
                for group in requests.iter() {
                    check_cancelled(cancelled)?;
                    size = size
                        .checked_add(group.len())
                        .filter(|size| *size <= self.validator.limits().bytes)
                        .ok_or(PayloadSourceError::LimitExceeded)?;
                }
                let snapshot = ExecutionRequestsSnapshot::from_native_groups(&requests)
                    .map_err(PayloadSourceError::Requests)?;
                if snapshot.root() != summary.summary().requests_root {
                    return Err(PayloadSourceError::SourceMismatch);
                }
                check_cancelled(cancelled)?;
                Ok(ExecutionQuerySource::ExecutionRequests { snapshot, metadata })
            }
            ExecutionQueryObject::BlockAccessList => {
                let raw =
                    executed.as_ref().and_then(|block| block.bal().map(|bal| bal.as_raw().clone()));
                drop(view);
                check_cancelled(cancelled)?;
                let raw = if let Some(raw) = raw {
                    raw
                } else {
                    self.provider
                        .bal_store()
                        .get_by_hash(metadata.native_block.hash)
                        .map_err(|error| read_error(PayloadSourceInput::BlockAccessList, error))?
                        .ok_or(PayloadSourceError::MissingInput(
                            PayloadSourceInput::BlockAccessList,
                        ))?
                };
                let limits = self.validator.limits();
                let snapshot =
                    BlockAccessListSnapshot::from_rlp(raw, limits.bal_bytes.min(limits.bytes))
                        .map_err(PayloadSourceError::Payload)?;
                if snapshot.root() != summary.summary().block_access_list_root {
                    return Err(PayloadSourceError::SourceMismatch);
                }
                check_cancelled(cancelled)?;
                Ok(ExecutionQuerySource::BlockAccessList { snapshot, metadata })
            }
            ExecutionQueryObject::ExecutionPayload => unreachable!(),
        }
    }
}

struct CapturedSource<N: ProviderNodeTypes> {
    view: ConsistentProvider<N>,
    executed: Option<ExecutedBlock<ExecutionPrimitives>>,
    entry: Option<Arc<SourceEntry>>,
    header: SealedHeader<ExecutionHeader>,
    metadata: PayloadSourceMetadata,
}

#[derive(Debug, Default)]
struct SourceEntry {
    receipts: Mutex<Option<Arc<ExecutionSource>>>,
    payload: Mutex<Option<Arc<ExecutionSource>>>,
}

const fn read_error(input: PayloadSourceInput, error: ProviderError) -> PayloadSourceError {
    PayloadSourceError::ProviderRead { input, error }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), PayloadSourceError> {
    if cancelled.load(Ordering::Relaxed) || reth_tasks::cancel::is_cancelled() {
        return Err(PayloadSourceError::Cancelled);
    }
    Ok(())
}

fn lock_cancelled<'a, T>(
    mutex: &'a Mutex<T>,
    cancelled: &AtomicBool,
) -> Result<MutexGuard<'a, T>, PayloadSourceError> {
    loop {
        check_cancelled(cancelled)?;
        if let Some(guard) = mutex.try_lock_for(Duration::from_millis(10)) {
            return Ok(guard);
        }
    }
}
