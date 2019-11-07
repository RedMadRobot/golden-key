<p align="center">
    <img src="https://user-images.githubusercontent.com/1762267/60340408-2676e580-99b4-11e9-8661-c42d4bb7461b.png" alt="GoldenKey">
</p>

# GoldenKey

Swift wrapper around CommonCrypto and Security frameworks

## Common Digest

Supported algorithms: MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512.

Stream hasher.

```swift
let sha = SHA256()
sha.update(data: Data("12".utf8))
sha.update(data: [1, 2])

let degest = sha.finalize()
```

One shot.

```swift
let digest = SHA256.hash(data: Data("123".utf8))
```

All hash functions return type conform to `Digest` protocol .
You can convert digest to common types like a `Data` and `[UInt8]`.

```swift
let data = Data(digest)
let bytes: [UInt8] = Array(digest)
```

## HMAC
hash-based message authentication code

Stream hasher.

```swift
let key = Data("secret_key".utf8)
let hmac = HMAC(algorithm: .md5, key: key)

hmac.update(data: Data("ab".utf8))
hmac.update(data: Data("cd".utf8))
let hash = hmac.finalize()
```

One shot.

```swift
let key = Data("secret_key".utf8)
let data = Data("abcd".utf8)

let hash = HMAC.hash(algorithm: .sha224, data: data, key: key)
```

## Setup for development

```bash
$ mkdir gyb
$ cd gyb
$ wget https://github.com/apple/swift/raw/master/utils/gyb
$ wget https://github.com/apple/swift/raw/master/utils/gyb.py
$ chmod +x gyb
```

# Efficient way to calculate hash of a large file

To calculate hash of a large file use `DispatchIO`.

In the example below `DispatchIO` reads a file by chunks and process every chunk by calling update method of `SHA256` class.

The default chunk size is set to 128 MB to limit maximum memory usage.

![Screenshot](./scr.png)

```swift
import Foundation
import GoldenKey

final class FileHash {
    
    private let workQueue: DispatchQueue
    private let dispatchIO: DispatchIO
    
    /// Opens and prepares a file for reading.
    /// - Parameter fileURL: URL of the file.
    /// - Parameter workQueue: DispatchQueue on which to perform work (read and calculating hash).
    /// - Parameter queue: DispatchQueue of the completion handler.
    /// - Parameter completion: Calls when the file closed. Useful when you want to calculate hash of multiple files sequentially.
    init(
        fileURL: URL,
        workQueue: DispatchQueue = .init(label: "work", qos: .userInitiated),
        queue: DispatchQueue = .main,
        completion: (() -> Void)? = nil) throws {
        
        self.workQueue = workQueue
        
        let fileHandle = try FileHandle(forReadingFrom: fileURL)
        
        dispatchIO = DispatchIO(
            type: .stream,
            fileDescriptor: fileHandle.fileDescriptor,
            queue: queue,
            cleanupHandler: { _ in
                fileHandle.closeFile()
                queue.async { completion?() }
            }
        )
        dispatchIO.setLimit(lowWater: Int.max)
    }
    
    /// Calculates hash of the file
    /// - Parameter hashFunctionType: Hash function type. SHA256.self for example.
    /// - Parameter chunkSize: Max memory usage. 128 MB by default.
    /// - Parameter queue: DispatchQueue of the completion handler.
    /// - Parameter completion: Completion handler.
    func calculateHash(
        hashFunctionType: Digest.Type,
        chunkSize: Int = 128 * 1024 * 1024,
        queue: DispatchQueue = .main,
        completion: @escaping (Result<Data, POSIXError>) -> Void) {
        
        let hashFunction = hashFunctionType.init()
        
        func readNextChunk() {
            dispatchIO.read(offset: 0, length: chunkSize, queue: workQueue) { [weak self] (done, data, error) in
                guard let self = self else { return }
                
                guard error == 0 else {
                    let error = POSIXError(POSIXErrorCode(rawValue: error)!)
                    self.dispatchIO.close(flags: .stop)
                    queue.async {
                        completion(.failure(error))
                    }
                    return
                }
                
                guard let data = data else { return }
                
                if data.isEmpty == false {
                    data.regions.forEach { hashFunction.update(data: $0) }
                }
                
                if done, data.isEmpty {
                    self.dispatchIO.close()
                    
                    let digest = hashFunction.finalize()
                    queue.async {
                        completion(.success(digest))
                    }
                }
                
                if done, data.isEmpty == false {
                    readNextChunk()
                }
            }
        }
        
        readNextChunk()
    }
    
}
```

## Usage example
```swift

extension Data {
    /// Presents Data in hex format
    var hexDescription: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
}

do {
    let fileURL = URL(string: "absolute_path_to_file")!
    let fileHash = try FileHash(fileURL: fileURL)
    fileHash.calculateHash(hashFunctionType: SHA256.self) { result in
        switch result {
        case .success(let hash):
            print(hash.hexDescription)
        case .failure(let error):
            print(error.localizedDescription)
        }
    }
} catch (let error) {
    print(error.localizedDescription)
}
```