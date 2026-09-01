# 📡 IoT & Embedded Systems Security Reference

*References: [ACSC IoT Secure by Design Guidance](https://www.cyber.gov.au/business-government/secure-design/secure-by-design/iot-secure-by-design-guidance-for-manufacturers) | [AS ETSI EN 303 645 Standard](https://store.standards.org.au/product/as-etsi-en-303-645-2023)*

---

## 1. The 13 IoT Secure-by-Design Principles (AS ETSI EN 303 645)

| Principle | Engineering Requirements |
|---|---|
| **1. No Default Passwords** | Unique, unpredictable per-device setup credentials; mandatory password change during onboarding; WebAuthn/MFA for cloud portals. |
| **2. Vulnerability Disclosure** | Maintain a public `/.well-known/security.txt` and clear vulnerability intake channel. |
| **3. Secure Updates (OTA)** | Cryptographically signed firmware (Ed25519/RSA-PSS) verified before flashing; anti-rollback protection. |
| **4. Secure Storage** | Store keys in Hardware Root of Trust (Secure Element, TPM, ATECC608, TrustZone); no plaintext in SPI flash. |
| **5. Data Protection** | Encrypt data at rest (AES-XTS/AES-GCM) and in transit; minimize telemetry data collection. |
| **6. Attack Surface Reduction** | **Disable JTAG, UART, SWD debug interfaces** on production hardware; close unused network ports. |
| **7. Secure Communication** | Mandate **TLS 1.3** for TCP (MQTTS port 8883) and **DTLS 1.3** for UDP (CoAPS port 5684) with mutual auth (mTLS). |
| **8. Multi-Stage Secure Boot** | ROM bootloader validates FSBL signature, which validates the kernel/firmware image before execution. |
| **9. Outage Resilience** | Support offline operation when cloud connectivity drops; fail to a safe default state. |
| **10. Telemetry & Tampering** | Monitor anomalous states (boot loops, flash corruption, physical chassis opening) and alert upstream SIEM. |
| **11. Factory Data Reset** | Hardware factory reset must cryptographically zeroize all flash sectors, user credentials, and network keys. |
| **12. Simple Installation** | Secure bootstrapping protocols (Wi-Fi Easy Connect / DPP, Bluetooth LE secure pairing). |
| **13. Input & Sensor Validation** | Strict bounds checking on all binary packet parsers (CAN bus, Modbus, protobuf, CBOR) to prevent buffer overflows. |

---

## 2. Hardware Lockdown & Production Build Checklist
- [ ] Debug ports (JTAG/UART/SWD) permanently blown via eFuse or disabled in firmware build macros.
- [ ] Flash memory readout protection (RDP Level 2 on STM32 / Secure Boot eFuses on ESP32) enabled.
- [ ] Local web management portals accessible only from local subnet by default.
