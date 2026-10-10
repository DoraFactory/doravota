# Client integration for Dora Vota 1.0.0

The SDK 0.55 account-number change applies to ordinary secp256k1 accounts as well as ML-DSA accounts. Accounts created after the upgrade receive hash-derived uint64 numbers with the high bit set (>= 2^63). Existing account numbers are retained. Do not confuse account number with the transaction sequence.

Preserve account numbers as decimal strings at JSON/API boundaries and as bigint or unsigned 64-bit values internally. Never convert them through JavaScript Number or a signed 64-bit integer. JSON.stringify cannot directly serialize bigint; encode it as a decimal string.

CosmJS 0.39.0 adds bigint account numbers and full uint64 Amino sign-document handling. Upgrade compatible CosmJS packages together and follow their runtime requirements. Updating a library does not by itself prove compatibility with an external wallet or hardware signer.

Before production use, create and fund a new address after the testnet upgrade. Verify account retrieval, Direct and Amino signatures, broadcasting and confirmed outgoing transfers using each supported wallet/version, frontend and signer. Also test an address first created by an incoming IBC transfer, then an outgoing transfer. Keep an existing low-numbered account as a control. Record wallet/library versions and transaction hashes. Include Ledger only when tested on actual hardware.

Transaction-search integrations should use the supported query expression, not the removed events parameter. Wasm smart-query and execution endpoints are removed; use the archive API for retained raw state. See VALIDATOR-1.0.0.md and WASM-RETIREMENT.md.
