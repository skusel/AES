# AES
This is an implementation of the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm, also known as Rijndael. This implementation supports AES-128, AES-192, and AES-256 key sizes. It also supports the ECB mode of operation. PKCS#7 padding is used to fill blocks of plaintext that do not meet the 16 byte block size requirement.

## Design goals
Written as a fun side project, the main purpose was to implement a working AES algorithm. At the same time, I wanted to provide an easy to use interface for encrypting and decrypting files using AES.

In general, I preferenced quick look-ups over code size. The key schedule is precomputed rather than done "on-the-fly". The computational overhead for a precomputed key schedule is less than that of an "on-the-fly" generated key schedule. Similarly, an AES s-box and inverse s-box is stored in two 256-byte arrays. The array look-up time is faster than the inverse GF(2^8) and affine mapping computation that would otherwise be needed. On the other hand, the "mix columns" step performs [finite field multiplication](https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication) using a version of the peasent multiplication algorithm. This algorithm is slower than a table lookup, but prevents the need for finite field multiplication tables in code.

## Validation
Unit tests test were written that check against output of known working implementations of the AES alogirthm or from the [AES publication](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf) itself. 

This library has not yet implemented unit tests that check against NIST Known Answer Test (KAT) vectors. These checks may be added in the future.

Please note, this library does **not** acheive NIST FIPS 140-2 validation. If you are trying to encrypt information that is very secret or highly confidential file with AES, you should seek a crypto library with FIPS 140-2 validation.

## Integration
There are several ways to include this library in your source. 

### CMake
If you are using CMake, the easiest way to do so is to use `FetchContent`.

Example:
```
include(FetchContent)
FetchContent_Declare(
  lskuse_aes
  GIT_REPOSITORY https://github.com/skusel/AES.git
  GIT_TAG 1.0
)
FetchContent_MakeAvailable(lskuse_aes)
add_executable(foo ...)
target_link_libraries(foo PRIVATE lskuse_aes::lskuse_aes)
```

You can also add this library as a sub-directory in your project and include it in you CMake that way. A common way of doing this is to include this repository as a git submodule, but you can also download the source.

Example:
```
add_subdirectory(lskuse_aes)
add_executable(foo ...)
target_link_libraries(foo PRIVATE lskuse_aes::lskuse_aes)
```

### Headers
This project has 2 public headers. They can be included with:
```
#include <lskuse/aes.h>
#include <lskuse/aesversion.h>
```

## Using the library
The library provides a simply interface for users.

To encrypt a file:
```
using namespace lskuse; // added for convenience

// encrypt with 16-byte key
auto status = AES::encrypt(Mode::ECB, KeyLen::LEN_128, Padding::PKCS7, 
                           "/path/to/plaintext/file", "01234567890abcdef",
                           "/path/to/output/ciphertext/file");

// encrypt with 24-byte key
status = AES::encrypt(Mode::ECB, KeyLen::LEN_192, Padding::PKCS7, 
                      "/path/to/plaintext/file", "01234567890abcdef01234567", 
                      "/path/to/output/ciphertext/file");

// encrypt with 32-byte key
status = AES::encrypt(Mode::ECB, KeyLen::LEN_256, Padding::PKCS7, 
                      "/path/to/plaintext/file", "012346789abcdef0123456789abcdef",
                      "/path/to/output/ciphertext/file");

// OR

// encrypt with 16-byte key
AES aes0(Mode::ECB, KeyLen::LEN_128, Padding::PKCS7);
aes0.encrypt("/path/to/plaintext/file", "0123456789abcdef", 
             "/path/to/output/ciphertext/file");

// encrypt with 24-byte key
AES aes1(Mode::ECB, KeyLen::LEN_192, Padding::PKCS7);
aes1.encrypt("/path/to/plaintext/file", "0123456789abcdef01234567", 
             "/path/to/output/ciphertext/file");

// encrypt with 32-byte key
AES aes2(Mode::ECB, KeyLen::LEN_256, Padding::PKCS7);
aes2.encrypt("/path/to/plaintext/file", "0123456789abcdef0123456789abcdef", 
             "/path/to/output/ciphertext/file");
```

To decrypt a file:
```
// decrypt with 16-byte key
auto status = AES::decrypt(Mode::ECB, KeyLen::LEN_128, Padding::PKCS7, 
                           "/path/to/ciphertext/file", "01234567890abcdef",
                           "/path/to/output/plaintext/file");

// decrypt with 24-byte key
status = AES::decrypt(Mode::ECB, KeyLen::LEN_192, Padding::PKCS7, 
                      "/path/to/ciphertext/file", "01234567890abcdef01234567", 
                      "/path/to/output/plaintext/file");

// decrypt with 32-byte key
status = AES::decrypt(Mode::ECB, KeyLen::LEN_256, Padding::PKCS7, 
                      "/path/to/ciphertext/file", "012346789abcdef0123456789abcdef",
                      "/path/to/output/plaintext/file");

// OR

// decrypt with 16-byte key
AES aes0(Mode::ECB, KeyLen::LEN_128, Padding::PKCS7);
status = aes0.encrypt("/path/to/ciphertext/file", "0123456789abcdef", 
                      "/path/to/output/plaintext/file");

// decrypt with 24-byte key
AES aes1(Mode::ECB, KeyLen::LEN_192, Padding::PKCS7);
status = aes1.encrypt("/path/to/ciphertext/file", "0123456789abcdef01234567", 
                      "/path/to/output/plaintext/file");

// decrypt with 32-byte key
AES aes2(Mode::ECB, KeyLen::LEN_256, Padding::PKCS7);
status = aes2.encrypt("/path/to/ciphertext/file", "0123456789abcdef0123456789abcdef", 
                      "/path/to/output/plaintext/file");
```

Reading a status message:
```
AES::Status status;
status.m_success; // true if operation was successful, otherwise false
status.m_message; // reason for failure
```

Obtaining the library version:
```
std::cout << "Using lskuse_aes version: " 
          << LSKUSE_AES_VERSION_MAJOR << "."
          << LSKUSE_AES_VERSION_MINOR << std::endl;
```

## Contributing
Please see [CONTRIBUTING.md](https://github.com/skusel/AES/blob/main/CONTRIBUTING.md) for information on how to contribute to this project.

## Licensing
This software is licensed under the MIT License. Please see [LICENSE](https://github.com/skusel/AES/blob/main/LICENSE) for more details.

## Author
Larry Skuse

## References
- [AES key schedule Wikipedia Page](https://en.wikipedia.org/wiki/AES_key_schedule)
- [Chapter 4 of Understanding Cryptography](https://www.crypto-textbook.com/download/Understanding-Cryptography-Chapter4.pdf) by C. Parr and J. Pelzl
- [Federal Information Processing Standards Publication 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [Finite Field Multiplication Wikipedia Section](https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication)
- [Rijndael S-box Wikipedia Page](https://en.wikipedia.org/wiki/Rijndael_S-box)

