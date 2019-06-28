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
let digest = SHA256.hash(Data("123".utf8))
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

hmac.combine(Data("ab".utf8))
hmac.combine(Data("cd".utf8))
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
