import Foundation
import CommonCrypto

class AES {

    private var keyLength: Int = 16

    // MARK: - Set Key Length

    func setKeyLen(_ k: Int) throws {
        guard k == 16 || k == 24 || k == 32 else {
            throw NSError(
                domain: "AES",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "AES key length must be 16, 24, or 32 bytes"
                ]
            )
        }

        keyLength = k
    }

    // MARK: - Variant Name

    func variantName() -> String {
        return "AES\(keyLength * 8)"
    }

    // MARK: - Supported Variants

    func variants() -> [Int] {
        return [16, 24, 32]
    }

    // MARK: - Encrypt

    func encrypt(_ plaintext: Data, key: Data) throws -> Data {

        guard key.count == keyLength else {
            throw NSError(
                domain: "AES",
                code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Invalid key length. Expected \(keyLength) bytes, got \(key.count) bytes"
                ]
            )
        }

        guard plaintext.count % kCCBlockSizeAES128 == 0 else {
            throw NSError(
                domain: "AES",
                code: 3,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Plaintext length must be a multiple of 16 bytes"
                ]
            )
        }

        return try crypt(
            data: plaintext,
            key: key,
            operation: CCOperation(kCCEncrypt)
        )
    }

    // MARK: - Decrypt

    func decrypt(_ ciphertext: Data, key: Data) throws -> Data {

        guard key.count == keyLength else {
            throw NSError(
                domain: "AES",
                code: 4,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Invalid key length. Expected \(keyLength) bytes, got \(key.count) bytes"
                ]
            )
        }

        guard ciphertext.count % kCCBlockSizeAES128 == 0 else {
            throw NSError(
                domain: "AES",
                code: 5,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Ciphertext length must be a multiple of 16 bytes"
                ]
            )
        }

        return try crypt(
            data: ciphertext,
            key: key,
            operation: CCOperation(kCCDecrypt)
        )
    }

    // MARK: - AES ECB Crypt

    private func crypt(
        data: Data,
        key: Data,
        operation: CCOperation
    ) throws -> Data {

        var output = Data(count: data.count)
        var outputLength: size_t = 0

        let status = output.withUnsafeMutableBytes { outputBuffer in

            data.withUnsafeBytes { dataBuffer in

                key.withUnsafeBytes { keyBuffer in

                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBuffer.baseAddress,
                        key.count,
                        nil,
                        dataBuffer.baseAddress,
                        data.count,
                        outputBuffer.baseAddress,
                        outputBuffer.count,
                        &outputLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw NSError(
                domain: "AES",
                code: Int(status),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "AES operation failed with status \(status)"
                ]
            )
        }

        output.removeSubrange(outputLength..<output.count)

        return output
    }
}
