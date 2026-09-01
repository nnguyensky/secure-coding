# 🔐 Cryptographic Key Management & PQC Reference

*References: [Managing cryptographic keys and secrets](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/managing-cryptographic-keys-and-secrets) | [ACSC ISM Cryptography](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-cryptography) | [NIST PQC Standards (FIPS 203/204)](https://csrc.nist.gov/projects/post-quantum-cryptography)*

---

## 1. Key Management Plan (KMP) Lifecycle (FIPS 140-3)
- **Separation of Keys from Code**: Hardcoded API keys, private keys, or certificates in source files or configuration manifests are strictly prohibited.
- **Hardware Root of Trust**: Master keys and root certificates must be generated and stored in Hardware Security Modules (HSMs) or Cloud KMS complying with **FIPS 140-3**.
- **Cryptoperiods**:
  - **Originator Usage Period (OUP)**: Period during which key creates signatures/encryption ($\le 365\text{ days}$).
  - **Recipient Usage Period (RUP)**: Period during which data may be decrypted/verified.
  - **Automated Rotation**: Schedule automated rotation (90–365 days); test emergency rollover procedures annually.

---

## 2. Envelope Encryption Pattern
```mermaid
flowchart LR
    subgraph KMS["Cloud KMS / HSM (FIPS 140-3)"]
        KEK["Key Encryption Key (KEK)"]
    end
    subgraph App["Application Memory"]
        DEK["Data Encryption Key (DEK)<br/>(Ephemeral AES-256-GCM)"]
        Payload["Plaintext Payload"]
        Ciphertext["Encrypted Payload + Wrapped DEK"]
    end
    KEK -->|Wraps / Decrypts| DEK
    DEK -->|Encrypts / Decrypts| Payload
    Payload --> Ciphertext
```
1. Client requests KMS to generate a data key: returns plaintext DEK and ciphertext wrapped DEK.
2. Client encrypts payload locally using plaintext DEK with **AES-256-GCM** or **ChaCha20-Poly1305**.
3. Plaintext DEK is immediately zeroized from memory. Ciphertext and wrapped DEK are stored together.

---

## 3. Ephemeral Workload Identity (OIDC Federation)
- Replace static, long-lived API tokens and service account keys with short-lived **OpenID Connect (OIDC)** identity tokens:
  - AWS IAM Roles for Service Accounts (IRSA) / EKS Pod Identity
  - Google Cloud Workload Identity Federation
  - Azure Managed Identities & Workload ID

---

## 4. Post-Quantum Cryptography (PQC) Transition Checklist
Design crypto agility into protocols to prepare for quantum decryption threats:
- **Key Encapsulation (KEM)**: Transition from RSA/ECDH to **ML-KEM (FIPS 203)** (formerly Kyber).
- **Digital Signatures**: Transition from RSA/ECDSA/Ed25519 to **ML-DSA (FIPS 204)** (formerly Dilithium) and **SLH-DSA (FIPS 205)** (formerly SPHINCS+).
- **Hybrid Exchange**: Deploy hybrid TLS key exchange (X25519 + ML-KEM-768) during transition periods.
