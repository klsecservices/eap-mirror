# EAP-TLS Network packet-captures 

Network dumps were made in our lab environment with Mikrotik router.

When doing 802.1x over Ethernet, to EAPOL-start request Mikrotik replies to `Nearest-non-TPMR-bridge` instead of using MAC-address that sent the EAPOL-start request (like Cisco does). 

### `normal/`

Contains normal 802.1x flow with two different clients attempting 802.1x authentication:

- `employee1@fictional-bank.ru` connects via WiFi
- `employee2@fictional-bank.ru` connects over Ethernet 

### `attack/`

Contains logs and captures of 802.1x flow when EAP-Mirror attack is executed:

1. `employee1@fictional-bank.ru` connects to rogue WiFi Access Point setup by Attacker ("EvilTwin")
2. Attacker is connected to Ethernet port and forwards `employee1@fictional-bank.ru` authentication
3. Attacker is successfully authenticates as `employee1@fictional-bank.ru` over Ethernet

