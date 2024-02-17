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
secure_string pad_pkcs7(const secure_string& input);
void aes_enc_cbc(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
void aes_enc_ecb(const byte key[KEY_SIZE], const secure_string& ptext, secure_string& ctext);
int aes_enc_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag);

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

    // Load Plain text
    std::ifstream input_file(argv[5]);
    if (!input_file) {
        std::cerr << "Failed to open input file: " << argv[5] << std::endl;
        return 1;
    }
    secure_string ptext((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
    ptext.erase(std::find_if(ptext.rbegin(), ptext.rend(),
                    [](unsigned char ch) { return !std::isspace(ch); }).base(),
                    ptext.end());

    secure_string ctext;

    // Read key, IV and AAD from files
    std::vector<byte> key, iv, aad;
    read_hex_file(argv[1], key);
    read_hex_file(argv[2], iv);
    read_hex_file(argv[3], aad);

    // Encrypt based on mode
    if (std::string(argv[4]) == "cbc") {
        // CBC mode
        aes_enc_cbc(key.data(), iv.data(), pad_pkcs7(ptext), ctext);
    } else if (std::string(argv[4]) == "ecb") {
        // ECB mode
        aes_enc_ecb(key.data(), pad_pkcs7(ptext), ctext);
    } else if (std::string(argv[4]) == "gcm"){
        std::vector<byte> ciphertext(ptext.size());
        std::vector<byte> tag(EVP_GCM_TLS_TAG_LEN);
        aes_enc_gcm((unsigned char*)ptext.data(), ptext.size(), aad.data(), aad.size(),
                key.data(), iv.data(), iv.size(), ciphertext.data(), tag.data());

        // Append the tag to the ciphertexts
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

        // Assign the ciphertext to ctext
        ctext.assign(ciphertext.begin(), ciphertext.end());
    }

    // Open the output file for writing ciphertext
    std::ofstream output_file(argv[6], std::ios::binary);
    if (!output_file) {
        std::cerr << "Failed to open output file: " << argv[6] << std::endl;
        return 1;
    }
    // Write the ciphertext to the output file
    output_file.write(reinterpret_cast<const char*>(ctext.data()), ctext.size());
 
    // Open another output file for writing hexadecimal ciphertext
    std::ofstream hex_output_file("hex_" + std::string(argv[6]), std::ios::binary);
    if (!hex_output_file) {
        std::cerr << "Failed to open output file: hex_" << argv[6] << std::endl;
        return 1;
    }
    // Write the hexadecimal ciphertext to the output file
    for (unsigned char c : ctext) {
        hex_output_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }

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

// Add PKCS#7 Padding to the Plaintext
secure_string pad_pkcs7(const secure_string& input) {

    secure_string padded = input;
    byte padding_len = BLOCK_SIZE - (input.size() % BLOCK_SIZE);
    padded.insert(padded.end(), padding_len, padding_len);
    return padded;
}

void aes_enc_cbc(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key, iv);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptInit_ex failed");

    ctext.resize(ptext.size()+BLOCK_SIZE);

    int out_len1 = (int)ctext.size();

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");
  
    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(out_len1 + out_len2);
}

void aes_enc_ecb(const byte key[KEY_SIZE], const secure_string& ptext, secure_string& ctext) 
{
    if (ptext.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Input size must be a multiple of block size");
    }

    ctext.resize(ptext.size());
    for (size_t i = 0; i < ptext.size(); i += BLOCK_SIZE) {
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            ctext[i + j] = ptext[i + j] ^ key[j];
        }
    }
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_enc_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
