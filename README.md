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
You can convert digest to common types like a `Data`, `String` or `[UInt8]`.

```swift
let data = Data(digest)
let bytes: [UInt8] = Array(digest)
let string = String(data: Data(digest), encoding: .utf8)
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
