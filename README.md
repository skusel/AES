![GitHub](https://img.shields.io/github/license/skusel/AES)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/skusel/AES/ubuntu)
![GitHub repo size](https://img.shields.io/github/repo-size/skusel/AES)

# AES
This is an implementation of the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm, also known as Rijndael. This implementation supports AES-128, AES-192, and AES-256 key sizes. It also supports the ECB mode of operation. PKCS#7 padding is used to fill blocks of plaintext that do not meet the 16 byte block size requirement.

## Design goals
Written as a fun side project, the main purpose was to implement a working AES algorithm. At the same time, I wanted to provide an easy to use interface for encrypting and decrypting files using AES.

I also wanted the library to support binary keys and data. As a result, the main interface accepts the key as a `const char*`. This allows the user to set each of the key's bytes to any value in the range [0, 255] or pass the key as an ascii string (i.e. "0123456789abcdef"). It will stop reading the key's bytes when the expected key length is hit - 16 for AES-128, 24 for AES-192, and 32 for AES-256. Additionally, the files are read in and written to as binary data, so this library is capable of encrypting and decrypting a wide range of file types.

For the most part, I preferenced quick look-ups over reduced library size. The key schedule is precomputed and stored in a vector rather than computed "on-the-fly". Similarly, an AES s-box and inverse s-box are stored in two 256-byte arrays, which is faster than the inverse GF(2^8) and affine mapping computation that would otherwise be needed. On the other hand, the "mix columns" step performs [finite field multiplication](https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication) using a variation of the peasent multiplication algorithm. This algorithm is slower than a table lookup but prevents the need for finite field multiplication tables in code.

## Validation
Unit tests test were written to check against output of known working implementations of the AES alogirthm or example values in the [AES publication](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf). 

This library has not implemented unit tests for NIST Known Answer Test (KAT) vectors yet. These checks may be added in the future.

Please note, this library does **not** acheive NIST FIPS 140-2 validation. If you are trying to encrypt information that is very secret or highly confidential with AES, you should seek a crypto library with FIPS 140-2 validation.

## Integration
There are several ways to include this library in your source tree. 

### CMake
If you are using CMake, the easiest way to do so is to use `FetchContent`.

Example:
```
include(FetchContent)
FetchContent_Declare(
  lskuse_aes
  GIT_REPOSITORY https://github.com/skusel/AES.git
  GIT_TAG v1.0
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
The library provides a simple interface for users.

All code in this section is written assuming
```
using namespace lskuse;
```
was declared earlier in the translation unit.

To encrypt a file:
```
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

## Author(s)
- Larry Skuse

## References
- [AES calculator](https://www.codeusingjava.com/tools/aes)
- [AES key schedule Wikipedia Page](https://en.wikipedia.org/wiki/AES_key_schedule)
- [Chapter 4 of Understanding Cryptography by C. Parr and J. Pelzl](https://www.crypto-textbook.com/download/Understanding-Cryptography-Chapter4.pdf)
- [Federal Information Processing Standards Publication 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [Finite Field Multiplication Wikipedia Section](https://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication)
- [PKCS padding method - IBM](https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method)
- [Rijndael S-box Wikipedia Page](https://en.wikipedia.org/wiki/Rijndael_S-box)

