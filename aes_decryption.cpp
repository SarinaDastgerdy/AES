#include <iostream>
#include <string>
#include <memory>
#include <limits>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <vector>
#include <fstream>
#include <sstream>
// Lib used for reading from files properly
#include <algorithm> 
#include <cctype> 
#include <iterator>
// Lib used for decoding & encodeing base 64
#include <openssl/bio.h> 
#include <openssl/buffer.h>
#include <openssl/evp.h>
// Error Handling
#include <openssl/err.h>

// Ref. https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Padding
static const unsigned int KEY_SIZE = 16;
static const unsigned int BLOCK_SIZE = 16;

template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p); 
    }
    
    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }
    
    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;


void handleErrors(void);
void read_hex_file(const std::string& filename, std::vector<byte>& data);
secure_string hex_to_secure_string(const std::vector<byte>& hex_data);
secure_string unpad_pkcs7(const secure_string& input);
void aes_dec_cbc(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);
void aes_dec_ecb(const byte key[KEY_SIZE], const secure_string& ctext, secure_string& rtext);
int aes_dec_gcm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext);


int main(int argc, char* argv[])
{
    // Foramat of Input
    if (argc != 7) {
        std::cerr << "Usage: " << argv[0] << " <key_file> <iv_file> <AAD file> <mode> <input_file> <output_file>\n";
        return 1;
    }

    // Load the necessary cipher
    if (std::string(argv[4]) == "cbc") {
        EVP_add_cipher(EVP_aes_128_cbc());
    } else if (std::string(argv[4]) != "ecb" && std::string(argv[4]) != "gcm") {
        std::cerr << "Invalid mode\n";
        return 1;
    } 
 
    secure_string rtext;

    // Read key, IV and AAD from files
    std::vector<byte> key, iv, aad, encrypted_text_with_tag;
    read_hex_file(argv[1], key);
    read_hex_file(argv[2], iv);
    read_hex_file(argv[3], aad);
    read_hex_file(argv[5], encrypted_text_with_tag);

    // Separate encrypted text and tag
    const int tag_size = EVP_GCM_TLS_TAG_LEN;
    std::vector<byte> encrypted_text(encrypted_text_with_tag.begin(), encrypted_text_with_tag.end() - tag_size);
    std::vector<byte> tag(encrypted_text_with_tag.end() - tag_size, encrypted_text_with_tag.end());

    
    secure_string ctext = hex_to_secure_string(encrypted_text);

    // Decrypt Based on Mode
    if (std::string(argv[4]) == "cbc") {
        // CBC mode
        aes_dec_cbc(key.data(), iv.data(), ctext, rtext);
    } else if (std::string(argv[4]) == "ecb") {
        // ECB mode
        aes_dec_ecb(key.data(), ctext, rtext);
    } else if (std::string(argv[4]) == "gcm"){
        // GCM mode
        std::vector<byte> decrypted_text(encrypted_text.size()); // Allocate space for decrypted text
        int plaintext_len = aes_dec_gcm(encrypted_text.data(), encrypted_text.size(), aad.data(), aad.size(),
                    tag.data(), key.data(), iv.data(), iv.size(), decrypted_text.data());

        if (plaintext_len < 0) {
            std::cerr << "Decryption failed\n";
            return 1;
        }

        rtext.assign(decrypted_text.begin(), decrypted_text.begin() + plaintext_len);
    }
    
  
    // Open the output file for writing Recoveredtext
    std::ofstream output_file(argv[6], std::ios::binary);
    if (!output_file) {
        std::cerr << "Failed to open output file: " << argv[6] << std::endl;
        return 1;
    }

    // Write the ciphertext to the output file
    output_file.write(reinterpret_cast<const char*>(rtext.data()), rtext.size());

    return 0;
}

// Reading Inputs from File
void read_hex_file(const std::string& filename, std::vector<byte>& data) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Read hex data from file
    std::string hex_str;
    file >> std::hex >> hex_str;

    // Convert hex string to bytes
    for (size_t i = 0; i < hex_str.size(); i += 2) {
        byte byte_val = static_cast<byte>(std::stoi(hex_str.substr(i, 2), nullptr, 16));
        data.push_back(byte_val);
    }
}

// Convert base16_Cipher Text to base64_Cipher
secure_string hex_to_secure_string(const std::vector<byte>& hex_data) {
    secure_string result;
    result.reserve(hex_data.size()); // Reserve space for all bytes in the hex data

    for (size_t i = 0; i < hex_data.size(); ++i) {
        result.push_back(static_cast<char>(hex_data[i])); // Append each byte to the secure_string
    }

    return result;
}

// Remove PKCS#7 Padding from the Ciphertext
secure_string unpad_pkcs7(const secure_string& input) {
    if (input.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid input size");
    }
    byte padding_len = input.back();
    if (padding_len > BLOCK_SIZE || padding_len == 0) {
        throw std::runtime_error("Invalid padding length");
    }
    return secure_string(input.begin(), input.end() - padding_len);
}

void aes_dec_cbc(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Recovered text contracts upto BLOCK_SIZE
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed");
  
    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0]+out_len1, &out_len2);

    if (rc != 1)
      throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
    rtext.resize(unpad_pkcs7(rtext).size());
}

void aes_dec_ecb(const byte key[KEY_SIZE], const secure_string& ctext, secure_string& rtext) {
    if (ctext.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Input size must be a multiple of block size");
    }

    rtext.resize(ctext.size());
    for (size_t i = 0; i < ctext.size(); i += BLOCK_SIZE) {
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            rtext[i + j] = ctext[i + j] ^ key[j];
        }
    }
    rtext.resize(unpad_pkcs7(rtext).size());
    
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_dec_gcm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext){
                    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
 }
