# A SHA-256 Hash That Is Also a Valid ECDSA Signature

```
SHA256(00000000000000000200a8013bbb8678)
    = 301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302
```

That 32-byte hash is simultaneously a valid BIP 66 DER-encoded ECDSA signature. It was used to spend a Bitcoin UTXO on mainnet — the hash itself *is* the signature.


## What Makes a Hash "Also a Signature"?

A Bitcoin ECDSA signature is DER-encoded as:

```
30 [length] 02 [r-length] [r] 02 [s-length] [s] [sighash-type]
```

For our 32-byte hash to parse as a valid signature, specific bytes must land in exact positions:

```
30 1D 02 0A [r: 10 bytes] 02 0F [s: 15 bytes] 02
│  │  │  │                 │  │                 └─ sighash = SIGHASH_NONE
│  │  │  └─ r is 10 bytes  │  └─ s is 15 bytes
│  │  └─ INTEGER tag        └─ INTEGER tag
│  └─ 29 bytes remaining
└─ SEQUENCE tag
```

BIP 66 also demands: no unnecessary leading zeros, positive values (first byte < 0x80), and non-zero r and s. In total, 7 byte positions must have exact values, plus validity constraints on the first byte of r and s. The probability of a random SHA-256 hash satisfying all of this is roughly **2^−51**.


## Finding the Needle

2^51 is about 2 quadrillion attempts. The search is embarrassingly parallel: try a 16-byte input, hash it, check if the output is valid DER.

Since the input is only 16 bytes, SHA-256 processes it as a single 64-byte block — one compression function call per attempt. This is extremely fast on GPUs.

A custom CUDA kernel does the SHA-256 compression and DER validity check per thread. We rented 8× NVIDIA RTX 5090 GPUs on [vast.ai](https://vast.ai) at ~$3.50/hour. Each GPU sustained ~22 billion hashes per second, for a combined rate of **~180 GH/s**.

The search found a valid polyglot after ~185 trillion attempts in **~2.3 hours**, at a total cost of roughly **$8**.


## The 3-Byte Bitcoin Script

To actually use this on Bitcoin, we need a script that:
1. Takes a preimage from the spender
2. SHA-256 hashes it to produce the signature
3. Verifies that signature against a public key

The entire redeemScript is 3 bytes:

```
OP_SHA256 OP_SWAP OP_CHECKSIG    (hex: a87cac)
```

The spender provides `<pubkey> <preimage>` in the unlocking script. Execution:

| Step | Operation | Stack |
|------|-----------|-------|
| 0 | (initial) | `[pubkey, preimage]` |
| 1 | OP_SHA256 | `[pubkey, SHA256(preimage)]` |
| 2 | OP_SWAP | `[SHA256(preimage), pubkey]` |
| 3 | OP_CHECKSIG | `[true]` |

OP_CHECKSIG treats SHA256(preimage) as the signature and verifies it. Wrapped in P2SH, this gives the mainnet address `38UQFB5bG72TtdLaX52rHK7dJ4BWGiKTvg`.

Note that this address is universal — it's the same for everyone, since the redeemScript contains no embedded data. Anyone who knows a valid polyglot preimage can spend from it.


## ECDSA Key Recovery

We have a signature (the hash) but no private key. How do we get the public key for OP_CHECKSIG?

ECDSA key recovery: given a signature (r, s) and a message, you can compute the public key that would make the verification pass. In Bitcoin, the "message" is the transaction's sighash — a hash of the transaction data.

Since the sighash depends on which UTXO is being spent, each spend recovers a *different* public key. But the signature is always the same: SHA256(preimage). No private key is ever involved.

The sighash type is 0x02 (SIGHASH_NONE), which means the signature doesn't commit to the transaction's outputs. The spender can send the coins wherever they want.


## The Mainnet Transaction

The polyglot was used in a [mainnet transaction](https://mempool.space/tx/1b5fa01f54d9dca7758eef0b7f192dea8e0abd4b581408945021c207a8e6a761?showDetails=true) with a 0-value OP_RETURN output reading "ECDSA-SHA2 Polyglot 💪🤓🧡". The entire 777 sat input went to miner fees. Transaction size: 149 bytes.

Code: [github.com/robinlinus/sha2-ecdsa](https://github.com/robinlinus/sha2-ecdsa)
