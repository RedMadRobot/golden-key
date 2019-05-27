# GoldenKey

Swift wrapper around CommonCrypto and Security frameworks

## Common Digest

Supported algorithms: MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512.

Stream hasher.

```swift
let sha = SHA256()
sha.combine(Data("12".utf8))
sha.combine(Data("3".utf8))

let hash = sha.finalize()
```

One shot.

```swift
let hash2 = SHA256.hash(Data("123".utf8))
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
