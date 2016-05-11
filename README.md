# Secure File Transfer with Diffie-Hellman Key Agreement Protocol and AES

### Purpose

The purpose of this project is understanding and implementing multithreaded secure tcp file transfer using a secret key on AES that is generated and created on Diffie-Hellman key agreement protocol. 
Sender side generates prime (p), generator (g) and random number(a) to process Diffie-Hellman key agreement, and sends data that is required for calculation (sender public key “A”, p, and g) to receiver side. Receiver generates a random number (b) and sends its calculated public key “B” to sender. Sender calculates secret key with receiver’s B, and receiver calculates secret key with sender’s A. After that, this agreed secret key used in AES encryption/decryption of sended/received file. 
