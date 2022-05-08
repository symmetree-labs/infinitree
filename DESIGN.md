# Infinitree

## Wat dis

Infinitree is a deduplicated, encrypted database that provides native
versioning capabilities, and was designed to secure all metadata
related to the data, including the exact size.

## Use cases

 * Securely and efficiently record application state
 * Store application secrets on untrusted storage (e.g. to be used in Kubernetes)
 * Fast single-writer databases for arbitrary data shapes
 * Transparently query multiple cache layers: in-memory, disk, remote storage
 * Versioned backups in the cloud, or external hard drives
 * Encrypt and store entire workspaces for fast sync between computer
 * Easily sync & wipe data & encryption programs while travelling
 * Storage and sync backend for offsite backups

## Threat model

Infinitree considers the following things to be part of the threat model:

 * Protect data confidentiality, integrity and authenticity
 * The exact size of data should not be known
 * Individual user data shouldn't be attributable on shared storage
 * Once a data is shared, it is no longer secure.
 * Deleting data from the storage should be possible
 * Access to only the key and raw data should not be sufficient for
   full data compromise

## Design

Infinitree is designed to be portable and easy to implement in various
programming languages and operating systems. It prefers to be fast and
correct over providing more complex features.

Infinitree organizes user data into *trees*. The root of trust for a
tree is a master key. The master key for a tree can be derived
directly from the user passphrase using Argon2.

Data is stored in uniform *objects* with a hard-coded size of
4MB. This is to mask the exact size of the data.  An *object id* is 32
bytes of random, represented in base32.  Objects are padded with random
bytes when they are not fully utilised.

Infinitree distinguishes 2 types of objects, with slightly differing
internal structure:

 * Index objects
 * Storage objects
 
Parallelism is important for speed, and objects and their data are
optimised for parallel, random access.

### Encrypting data chunks

A storage object is a series of *chunks* that are individually LZ4
compressed, then encrypted using a symmetric ChaCha20-Poly1305 AED
construction.

In order to extract chunks from objects, the following needs to be known:

 * object id
 * start offset
 * compressed chunk size
 * Blake3 hash of plaintext
 
The ChaCha20-Poly1305 is parameterized as such:

    size:     4 bytes = size_of(data)
    
    key:     32 bytes = <index key | storage key>
    
    hash:    32 bytes = blake3(data)
    
    aead_key: 32 bytes = key XOR hash
    
    nonce: 32 bytes = (object_id[:4] XOR size) ++ object_id[4:]
    	
	cyphertext, tag = chacha_poly(aead_key, nonce, data, aad = none)
	
This parameterization allows for [convergent encryption][convergent_enc].

Such a construct also means that compromise of `key` in itself does
not necessarily result in full data compromise without access to the
metadata.

### Storage objects

Storage objects are tightly packed with chunks, and padded at the end
of the file with random bytes.

```
| ChaCha-Poly(LZ4(chunk 1)) | ChaCha-Poly(LZ4(chunk 2)) |
|               ChaCha-Poly(LZ4(chunk 3))               | 
|           ... ChaCha-Poly(LZ4(chunk 3))               | 
| ChaCha-Poly(LZ4(chunk 4)) | random padding            | 
```


To encrypt chunks in storage objects, a *storage key* is derived as a
subkey of the *master key* using the Blake 3 [key derivation
function][blake3_key_derive].

### Index objects

The *root object ID* is derived from the master key using the Blake 3
[key derivation function][blake3_key_derive].

Index objects behave in every way the same as storage objects, with 2
differences:

 * A separate *index key* is derived from the *master key*
 * The first 512 bytes of these objects are reserved for a header or
   filled with random

Root object:

```
| 512 bytes: ChaCha-Poly(LZ4(root pointer + random)) + tag |
| ChaCha-Poly(LZ4(chunk 1)) | ChaCha-Poly(LZ4(chunk 2))    |
|               ChaCha-Poly(LZ4(chunk 3))                  | 
|           ... ChaCha-Poly(LZ4(chunk 3))                  | 
| ChaCha-Poly(LZ4(chunk 4)) | random padding               | 
```

Index object:

```
| 512 bytes: random                                        |
| ChaCha-Poly(LZ4(chunk 1)) | ChaCha-Poly(LZ4(chunk 2))    |
|               ChaCha-Poly(LZ4(chunk 3))                  | 
|           ... ChaCha-Poly(LZ4(chunk 3))                  | 
| ChaCha-Poly(LZ4(chunk 4)) | random padding               | 
```

**Note:** it is not strictly a requirement for index objects to reserve
and fill the header with random. This is currently an implementation detail.

#### Header

The header contains the following 512 byte structure:

```
ChaCha-Poly(

offset: Network Endian 4 bytes: u32
size: Network Endian 4 bytes: u32
object_id: 32 bytes
hash: 32 bytes
tag: 16 bytes
random: 512 - 88 - 16 bytes = 408

)

tag: 16 bytes 
```

The header is decrypted or encrypted with the following parameters,
using the [standard chunk encryption method](#encrypting-data-chunks),
setting the `hash` to a 32 bytes of 0.

Since `hash` is only used as a transformation on the `key` to allow
convergent encryption, this use is safe and does not result in
weakening of security properties.

The data chunk that the header points to can allow bootstrapping and
deserialization of more complex structures, depending on the use case.

## Threat model

Looking at the threat model from the perspective of the following
attacker profiles:

 * Passive storage observer
 * Active storage compromise
 * Full client compromise (User)
 * Full client compromise (Administrator)
 
### Passive storage observer

A passive observer of the storage activity cannot create new objects,
but observe user activity on the storage.

A passive observer will be able to observe the amount of traffic a
user generates, and the objects they access in the duration of the
compromise.

A passive observer may be able to identify individual users based on
traffic correlation or by unique connection identifiers, such as IP
address.

### Active storage compromise

An active adversary on the storage can create new objects and modify
existing ones, plus monitor user activity.

An active adversary can overwrite stored objects in part or in whole,
in a targeted manner.

However, since they don't possess user keys, these modifications can
be detected by a user agent. In effect, the attack would be a DoS,
where an adversary can destroy data selectively.

### Full client compromise (User)

The client will possess all key information, storage provider
credentials, and access details they can intercept, using e.g. a
keylogger. THey, however, will not have access to key material stored
in memory unless they can force the user agent to dump state into an
accessible location.

### Full client compromise (Administrator)

The client will possess all key information, storage provider
credentials, and access details. Any locally stored object is safe
until the user unlocks the metadata referencing it. Once a stash is
opened on a client, the adversary will have read-write access to all
accessible data, local or remote.

## Deduplication

Infinitree uses deduplication of chunks to minimise the storage
use. Currently the algorithm is based on SeaHash, and is tuned towards
creating fewer chunks. I strongly suspect it needs some more effort to
fine-tune the performance.

Currently we create a split when the lower 13 bits of output of
SeaHash is 1. Running with this setting on the repo itself, I get
around 64k big chunks on average, and 10% re-use. I have not math'd
this out properly, but seemed reasonable enough.


## Portability

Infinitree is written in Rust to be easily portable across platforms. Rust can be
easily compiled to static binaries, which can be shared on e.g. a cloud
storage.

One aim is to require no installation or modification to an existing
operating system, although an installation package could provide
platform-specific integration for better user experience.

[blake3_key_derive]: https://docs.rs/blake3/latest/blake3/fn.derive_key.html
[convergent_enc]: https://en.wikipedia.org/wiki/Convergent_encryption
