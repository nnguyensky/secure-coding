# Solidity — secure snippets

Load only when writing smart contracts. Everything on-chain is public and every call is hostile:
there are no secrets, and any function anyone can call will be called with the worst arguments.

## Parameterized query — N/A
No SQL. The equivalent rule: never build calldata from untrusted strings; use typed `abi.encodeCall`.
```solidity
(bool ok, ) = target.call(abi.encodeCall(IVault.deposit, (amount)));
```

## Password hashing — N/A
Nothing on-chain is private, including hashed passwords. Authenticate with signatures (see below).

## Authenticated encryption — N/A
Do not encrypt on-chain; anyone can read state and calldata. Keep private data off-chain.

## Secure random — not from the chain
```solidity
// use a VRF (e.g. Chainlink VRF) or commit-reveal
// never: block.timestamp, blockhash, block.prevrandao or keccak256 of them for lotteries or selection
```

## Constant-time comparison — N/A
Timing is not observable on-chain in the same way; compare hashes with `==`.

## Temp files — N/A
No file system.

## Secure cookie — N/A
No cookies.

## Shell — N/A
No processes. The equivalent danger is `delegatecall` into an address someone else controls.
```solidity
// never: target.delegatecall(data) where target comes from a caller
```

## Input validation — require what you assume
```solidity
error InvalidAmount();
if (amount == 0 || amount > MAX_DEPOSIT) revert InvalidAmount();
if (to == address(0)) revert ZeroAddress();
```

## Output encoding — N/A
Front ends must escape token names and metadata they display; they are attacker-controlled strings.

## TLS — N/A
Transport is the node connection; use HTTPS/WSS RPC endpoints in the front end.

## Secrets — none on-chain
```solidity
// private variables are readable from storage; never put keys, passwords or answers in a contract
```

## Error handling — revert with custom errors, check every call
```solidity
error TransferFailed();
(bool ok, ) = payable(to).call{value: amount}("");
if (!ok) revert TransferFailed();
// ERC-20: use SafeERC20.safeTransfer — some tokens return false instead of reverting
```

## Secure logging — events
```solidity
event Withdrawn(address indexed account, uint256 amount);
emit Withdrawn(msg.sender, amount);
```

## File upload / path traversal — N/A
No file system; token URIs and metadata live off-chain and must be validated where they are rendered.

## Safe redirect — N/A
No HTTP.

## Cache-Control — N/A
No HTTP.

## Session — N/A
No sessions; use nonces in signed messages so a signature cannot be replayed.

## Password complexity — N/A
No passwords.

## File permissions — access control
```solidity
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
function pause() external onlyRole(PAUSER_ROLE) { _pause(); }
// never: require(tx.origin == owner) — a contract the owner calls can pass that check
```

## Encryption at rest — N/A
Chain state is public by design.

## Integrity verification — signatures with EIP-712 and nonces
```solidity
bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)));
address signer = ECDSA.recover(digest, signature);     // rejects malleable signatures and address(0)
if (signer != owner || block.timestamp > deadline) revert InvalidSignature();
```

## SSRF prevention — N/A
Contracts cannot make network requests; oracles must be trusted and their data bounded.

## CORS — N/A
No HTTP.

## Log injection prevention — N/A
Events are structured.

## Reentrancy — checks, effects, interactions
```solidity
function withdraw(uint256 amount) external nonReentrant {
    if (balances[msg.sender] < amount) revert Insufficient();   // checks
    balances[msg.sender] -= amount;                              // effects
    (bool ok, ) = payable(msg.sender).call{value: amount}("");  // interactions last
    if (!ok) revert TransferFailed();
}
```

## Compiler and arithmetic
```solidity
pragma solidity 0.8.28;          // pinned; >= 0.8 reverts on overflow
// `unchecked { }` only where you have proved the bound
```

## Upgrades and self-destruct
```solidity
// initializers: use OpenZeppelin Initializable and call _disableInitializers() in the constructor
// never: selfdestruct (deprecated); never leave an upgrade function without access control
```
