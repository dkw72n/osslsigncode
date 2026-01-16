#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

void handle_error(const char* msg) {
    std::cerr << "Error: " << msg << std::endl;
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Helper to clean and decode Base64 string
std::vector<unsigned char> base64_decode(const std::string& input) {
    // Remove non-base64 characters (mostly newlines)
    std::string clean_input;
    clean_input.reserve(input.size());
    for (char c : input) {
        if (isalnum(c) || c == '+' || c == '/' || c == '=') {
            clean_input += c;
        }
    }

    if (clean_input.empty()) return {};

    BIO *bio, *b64;
    int len = clean_input.length();
    
    // We allocate enough buffer. Decoded is approx 3/4 of encoded.
    std::vector<unsigned char> buffer(len);

    bio = BIO_new_mem_buf(clean_input.data(), len);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, buffer.data(), len);
    BIO_free_all(bio);

    if (decoded_len < 0) {
        return {};
    }
    
    buffer.resize(decoded_len);
    return buffer;
}


int main(int argc, char** argv) {
    if (argc != 4) {
        std::cout << "Usage: " << argv[0] << " <in.p7b> <sig> <out.p7b>" << std::endl;
        std::cout << "  in.p7b:  Input PKCS#7 file (DER or PEM) with placeholder signature" << std::endl;
        std::cout << "  sig:     File containing the new signature in Base64 format" << std::endl;
        std::cout << "  out.p7b: Output PKCS#7 file" << std::endl;
        return 1;
    }

    const char* p7b_path = argv[1];
    const char* sig_path = argv[2];
    const char* out_path = argv[3];

    // OpenSSL initialization
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Read input P7B
    BIO* in_bio = BIO_new_file(p7b_path, "rb");
    if (!in_bio) handle_error("Failed to open input P7B file");

    PKCS7* p7 = NULL;
    bool is_pem = false;
    
    // Try reading as PEM first
    p7 = PEM_read_bio_PKCS7(in_bio, NULL, NULL, NULL);
    if (p7) {
        is_pem = true;
    } else {
        BIO_reset(in_bio);
        p7 = d2i_PKCS7_bio(in_bio, NULL);
    }

    if (!p7) {
        BIO_free(in_bio);
        handle_error("Failed to parse PKCS#7 file (neither PEM nor DER)");
    }
    BIO_free(in_bio);

    // 2. Read Signature Base64 File
    std::ifstream sig_file(sig_path, std::ios::in | std::ios::binary);
    if (!sig_file) {
        PKCS7_free(p7);
        std::cerr << "Error: Failed to open sig file: " << sig_path << std::endl;
        return 1;
    }
    std::string sig_content((std::istreambuf_iterator<char>(sig_file)), std::istreambuf_iterator<char>());
    sig_file.close();

    std::vector<unsigned char> decoded_sig = base64_decode(sig_content);
    if (decoded_sig.empty()) {
        PKCS7_free(p7);
        std::cerr << "Error: Base64 decode failed or empty output (Check sig file content)." << std::endl;
        return 1;
    }
    
    // 3. Find SignerInfo and replace signature
    if (!PKCS7_type_is_signed(p7)) {
        PKCS7_free(p7);
        std::cerr << "Error: PKCS#7 file is not SignedData type." << std::endl;
        return 1;
    }
    
    STACK_OF(PKCS7_SIGNER_INFO) *signer_infos = PKCS7_get_signer_info(p7);
    if (!signer_infos || sk_PKCS7_SIGNER_INFO_num(signer_infos) == 0) {
        PKCS7_free(p7);
        std::cerr << "Error: No SignerInfo found in PKCS#7 file." << std::endl;
        return 1;
    }

    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(signer_infos, 0);
    
    // Replace enc_digest (SignatureValue)
    if (!ASN1_OCTET_STRING_set(si->enc_digest, decoded_sig.data(), decoded_sig.size())) {
        PKCS7_free(p7);
        handle_error("Failed to set new signature value");
    }

    // 4. Write output P7B
    BIO* out_bio = BIO_new_file(out_path, "wb");
    if (!out_bio) {
        PKCS7_free(p7);
        handle_error("Failed to open output P7B file");
    }

    int ret = 0;
    if (is_pem) {
        ret = PEM_write_bio_PKCS7(out_bio, p7);
    } else {
        ret = i2d_PKCS7_bio(out_bio, p7);
    }
    
    if (!ret) {
         BIO_free(out_bio);
         PKCS7_free(p7);
         handle_error("Failed to write PKCS#7 structure");
    }

    BIO_free(out_bio);
    PKCS7_free(p7);
    
    std::cout << "Success! Signature updated in " << out_path << std::endl;

    return 0;
}
