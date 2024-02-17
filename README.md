## AES Encryption and Decryption with OpenSSL

This project implements AES encryption and decryption in C++ using OpenSSL libraries. AES (Advanced Encryption Standard) is a widely-used symmetric encryption algorithm for securing sensitive data.

### Features

- Supports three encryption modes: ECB (Electronic Codebook), CBC (Cipher Block Chaining), and GCM (Galois/Counter Mode).
- Implements PKCS#7 padding for ensuring proper block alignment.
- Requires additional authentication data (AAD) input for GCM mode.
- Provides command-line interface for easy encryption and decryption of files.

### Usage

To encrypt or decrypt a file using this project, use the following command format:
- `<key_file>`: A file containing a 128-bit key as a hexadecimal string.
- `<iv_file>`: A file containing the initialization vector (IV) as a hexadecimal string.
- `<AAD_file>`: (For GCM mode only) A file containing additional authentication data.
- `<mode>`: Encryption mode (`ecb`, `cbc`, or `gcm`).
- `in=<input_file>`: Input file to be encrypted or decrypted.
- `out=<output_file>`: Output file to store the encrypted or decrypted result.

### Compilation and Usage

To compile the code, use the following command:  
'''bash
g++ -o out aes_encryption.cpp -lssl -lcrypto  
Once the code has been compiled, you can run the executable with the following command:  
```bash
./out key.txt iv.txt aad.txt ecb input.txt output.txt
```
Replace key.txt, iv.txt, aad.txt, input.txt, and output.txt with the actual filenames and parameters you intend to use.


### File Formats

- **Encryption Input**: The input file for encryption should contain the text in ASCII format.
- **Decryption Input**: The input file for decryption should contain the ciphertext in hexadecimal format.
- **Encryption Output**: The output of encryption will be in both ASCII and hexadecimal formats.
- **Decryption Output**: The output of decryption will be the plaintext in ASCII format.

### Resources

- [OpenSSL Documentation](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Padding): Learn more about EVP Symmetric Encryption and Decryption with OpenSSL.
- [OpenSSL Documentation](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode): Learn more about EVP Authenticated Encryption and Decryption with OpenSSL.

