# 🔐 Self-Sovereign Digital Identity Wallet

A decentralized identity management system built on Stacks blockchain that gives users complete control over their digital identity attributes.

## 🌟 Features

- 🆔 **Create Digital Identity**: Establish your sovereign identity on-chain
- 🔑 **Recovery Key Management**: Set and update recovery keys for account security
- 📝 **Attribute Management**: Add, update, and remove personal attributes
- 🔒 **Privacy Controls**: Set attributes as public or private
- 🤝 **Access Permissions**: Grant/revoke access to specific attributes
- ✅ **Verification Requests**: Handle identity verification workflows
- ⏰ **Time-based Access**: Set expiration times for permissions

## 🚀 Getting Started

### Prerequisites

```bash
npm install -g @hirosystems/clarinet-cli
```

### Installation

```bash
git clone <repository-url>
cd identity-wallet
clarinet console
```

## 📖 Usage

### Creating an Identity

```clarity
(contract-call? .identity-wallet create-identity (some 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7))
```

### Adding Attributes

```clarity
(contract-call? .identity-wallet add-attribute "email" u"user@example.com" false)
(contract-call? .identity-wallet add-attribute "name" u"John Doe" true)
```

### Granting Access

```clarity
(contract-call? .identity-wallet grant-access 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 "email" u1000)
```

### Requesting Verification

```clarity
(contract-call? .identity-wallet request-verification 'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE "name" u500)
```

## 🔍 Read-Only Functions

### Get Identity Information

```clarity
(contract-call? .identity-wallet get-identity 'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE)
```

### Get Attribute (respects privacy settings)

```clarity
(contract-call? .identity-wallet get-attribute 'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE "email")
```

### Check Access Permissions

```clarity
(contract-call? .identity-wallet has-access 'SP1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE "email")
```

## 🛡️ Security Features

- **Self-Sovereign**: Users maintain complete control over their data
- **Permission-Based Access**: Granular control over who can access what
- **Time-Limited Permissions**: Access can expire automatically
- **Recovery Mechanisms**: Set recovery keys for account restoration
- **Privacy by Default**: Attributes are private unless explicitly made public

## 🏗️ Architecture

The contract uses four main data structures:

1. **Identities**: Core identity records with recovery keys
2. **Identity Attributes**: Key-value pairs of personal data
3. **Access Permissions**: Time-bound access grants to specific attributes
4. **Verification Requests**: Workflow for identity verification processes

## 🔧 Error Codes

- `u100`: Not authorized
- `u101`: Identity not found
- `u102`: Attribute not found
- `u103`: Invalid signature
- `u104`: Permission denied
- `u105`: Identity already exists
- `u106`: Invalid expiry time

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🌐 Links

- [Stacks Documentation](https://docs.stacks.co/)
- [Clarity Language Reference](https://docs.stacks.co/clarity/)
- [Clarinet Documentation](https://github.com/hirosystems/clarinet)
```

**Git Commit Message:**
```
feat: implement self-sovereign digital identity wallet MVP with attribute management and access controls
```

**GitHub Pull Request Title:**
```
🔐 Add Self-Sovereign Digital Identity Wallet MVP
```

**GitHub Pull Request Description:**
```
## 🚀 What's Added

This PR introduces a complete Self-Sovereign Digital Identity Wallet system built on Stacks blockchain.

### ✨ Key Features
- **Identity Creation & Management**: Users can create and manage their digital identities
- **Attribute System**: Add, update, and remove personal attributes with privacy controls
- **Access Control**: Grant/revoke time-limited access to specific attributes
- **Verification Workflow**: Request and approve identity verification processes
- **Recovery Mechanisms**: Set recovery keys for account security

### 🏗️ Implementation Details
- Complete Clarity smart contract (200+ lines)
- Comprehensive error handling with descriptive error codes
- Privacy-first design with granular permission controls
- Time-based access expiration for enhanced security
- Read-only functions respecting privacy settings

### 📋 Contract Functions
- Identity lifecycle management
- Attribute CRUD operations
- Permission granting/revoking
- Verification
