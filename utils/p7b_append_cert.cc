#include <iostream>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/err.h>

// 简单的错误处理函数
void handle_error(const char* msg) {
    std::cerr << "Error: " << msg << std::endl;
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cout << "Usage: " << argv[0] << " <original.p7b> <cert_to_add.pem> <output.p7b>" << std::endl;
        return 1;
    }

    const char* p7b_path = argv[1];
    const char* cert_path = argv[2];
    const char* out_path = argv[3];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 1. 读取原始 P7B 文件
    BIO* in_p7_bio = BIO_new_file(p7b_path, "rb");
    if (!in_p7_bio) handle_error("Failed to open P7B file");

    bool is_pem = false;
    // 尝试读取为 PEM 格式
    PKCS7* p7 = PEM_read_bio_PKCS7(in_p7_bio, NULL, NULL, NULL);
    if (p7) {
        is_pem = true;
    } else {
        // 如果 PEM 失败，重置指针尝试读取为 DER 格式
        (void)BIO_reset(in_p7_bio); 
        p7 = d2i_PKCS7_bio(in_p7_bio, NULL);
    }
    
    if (!p7) handle_error("Failed to parse PKCS#7 structure (Check if file exists and format is valid)");
    BIO_free(in_p7_bio);

    // 2. 验证 PKCS7 类型是否支持包含证书
    // 通常 P7B 是 NID_pkcs7_signed (SignedData)
    if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
        PKCS7_free(p7);
        std::cerr << "Error: The P7B file is not of type SignedData or SignedAndEnvelopedData." << std::endl;
        return 1;
    }

    // 3. 读取要追加的新证书 (PEM格式)
    BIO* in_cert_bio = BIO_new_file(cert_path, "rb");
    if (!in_cert_bio) handle_error("Failed to open Certificate file");

    X509* new_cert = PEM_read_bio_X509(in_cert_bio, NULL, NULL, NULL);
    if (!new_cert) handle_error("Failed to parse Certificate (Ensure it is PEM format)");
    BIO_free(in_cert_bio);

    // 4. 将证书添加到 PKCS7 结构中
    // PKCS7_add_certificate 会处理 stack 的初始化和推入
    if (PKCS7_add_certificate(p7, new_cert) != 1) {
        X509_free(new_cert); // 如果添加失败，手动释放，否则 PKCS7 结构体会接管它
        handle_error("Failed to add certificate to PKCS7 structure");
    }
    // 注意：成功添加后，new_cert 的内存管理归 p7 对象所有，不需要手动 X509_free

    // 5. 将修改后的 PKCS7 写入新文件 (保持输入格式)
    BIO* out_bio = BIO_new_file(out_path, "wb");
    if (!out_bio) handle_error("Failed to open output file");

    int write_result = 0;
    if (is_pem) {
        write_result = PEM_write_bio_PKCS7(out_bio, p7);
    } else {
        write_result = i2d_PKCS7_bio(out_bio, p7);
    }

    if (write_result != 1) {
        handle_error("Failed to write output PKCS7");
    }

    std::cout << "Success! Certificate appended to " << out_path << (is_pem ? " (PEM)" : " (DER)") << std::endl;

    // 清理
    PKCS7_free(p7);
    BIO_free(out_bio);
    
    return 0;
}