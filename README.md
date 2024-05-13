# Secure Chat

## Description

Secure Chat is a Python-based application that facilitates secure communication between two parties over a network. The application employs various cryptographic algorithms to ensure confidentiality, integrity, and authenticity of messages exchanged between the users.

## Algorithm Implementation

The algorithm implementation involves the following steps:

1. **Diffie-Hellman (DH) Key Exchange**: 
   - Read DH parameters (q, α) from a file simulating being publicly accessed.
   - Generate public/private key pairs for DH.
   - Exchange DH public keys between Alice and Bob after signing them with ElGamal digital signature.
   - Compute the shared secret using DH.
   
2. **ElGamal Digital Signature**:
   - Read ElGamal parameters (q, α) from a file simulating being publicly accessed.
   - Generate public/private key pairs for ElGamal.
   - Sign DH public keys with ElGamal digital signature.
   - Verify signatures to ensure authenticity and close the connection if not verified.
   
3. **AES Encryption**:
   - Derive an AES 256-bit key from the DH shared secret using SHA256.
   - Encrypt and decrypt messages using AES.

## How to Run the Program

Follow these steps to run the program:

1. **Clone Repository**: 
   - Clone the repository to your local machine using `git clone https://github.com/MostafaMagdyy/Secure-Chat`.
   
2. **Navigate to Directory**: 
   - Open a terminal or command prompt and navigate to the project directory.

3. **Setup Parameters**:
   - Ensure you have the necessary DH and ElGamal parameters in a file accessible to both server and client, see **parameters** file for clarity.
   
4. **Start Server**:
   - Run the `server.py` script to start the server: `python server.py`.
   
5. **Start Client**:
   - Run the `client.py` script to start the client: `python client.py`.
   
6. **Start Chatting**:
   - Once the connection is established, you can start chatting securely using the provided interface.

7. **Terminate Connection**:
   - To terminate the connection, press `Ctrl+C` on any of the server and client terminals.
