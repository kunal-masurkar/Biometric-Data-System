# Biometric Data System

A secure Python application for managing biometric data with authentication, encryption, and access control.

## Overview

This system implements a comprehensive biometric data management platform with:

- Multi-factor authentication (username/password + reCAPTCHA)
- Role-based access control (admin, manager, user)
- AES-256 encryption for biometric data
- Secure storage and retrieval mechanism
- Biometric data collection and validation

## Features

- **User Management:** Register and authenticate users with different access levels
- **Access Control:** Role-based permissions for data access
- **Encryption:** AES-256 encryption for sensitive biometric information
- **Authentication:** Multi-layer authentication process
- **Storage:** Secure file-based storage for encrypted data

## Directory Structure

```
biometric-data-system/
│
├── biometric_system.py      # Main Python file with all the code
│
├── users.json               # Created automatically to store user credentials
│
├── secure_storage/          # Created automatically to store encrypted biometric data
│   ├── username1_biometric.enc
│   ├── username2_biometric.enc
│   └── ...
│
└── requirements.txt         # Lists dependencies
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/biometric-data-system.git
cd biometric-data-system
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python biometric_system.py
```

### Default Admin Credentials
- Username: `admin`
- Password: `admin123`

## Flow Diagram

The system follows this flow:

1. User authentication via username/password
2. reCAPTCHA verification
3. Biometric data collection
4. Data validation and preprocessing
5. AES-256 encryption
6. Secure storage
7. Role-based access control for retrieval

## Security Notes

This is a demonstration project and includes several security features, but for production use, consider:

- Using a proper database instead of file storage
- Implementing a more robust key management system
- Adding comprehensive logging
- Implementing session management
- Using hardware security modules for key storage
- Adding additional authentication factors

## Requirements

- Python 3.7+
- cryptography package
