# Luna Samples Documentation

This document provides a comprehensive overview of the samples available in the Luna Samples repository. These samples are designed to work with all variants of Luna General Purpose HSMs, including Luna Network HSM 7, Luna PCIe HSM 7, Luna USB HSM (U700), Luna Cloud HSM (DPoD), and earlier generations.

## Major Sample Groups

The repository is organized into three main sample groups, each targeting different programming languages and interfaces:

| Sample Group | Language | Description |
|-------------|----------|-------------|
| [C_Samples](#c_samples) | C | PKCS#11 interface samples for direct Luna HSM integration |
| [LunaJSP_Samples](#lunajsp_samples) | Java | Samples that use the Luna Java Security Provider (JSP) |
| [RestAPI_Python](#restapi_python) | Python | REST API samples for Luna Network HSM administrative tasks |

## C_Samples

The C_Samples directory contains examples written in C language that demonstrate how to use the PKCS#11 interface to interact with Luna HSMs. These samples cover a wide range of cryptographic operations and key management functions.

### Subdirectories

| Directory | Description | Number of Samples |
|-----------|-------------|-------------------|
| encryption | Samples demonstrating how to perform encryption | 8 |
| generating_keys | Samples demonstrating how to generate different types of cryptographic keys | 10 |
| signing | Samples showing how to perform signing and signature verification | 7 |
| object_management | Samples demonstrating how to manage keys and other objects | 10 |
| sfnt_extension | Samples demonstrating various SafeNet function (Vendor Defined Functions) | 3 |
| misc | Samples demonstrating various miscellaneous tasks | 8 |

Additionally, the root of C_Samples contains `Connect_and_Disconnect.c`, a basic sample that shows how to connect to and disconnect from a Luna HSM.

### Notable Samples

- **Key Generation**:
  - `CKM_AES_KEY_GEN_demo.c` - Demonstrates how to generate an AES key
  - `CKM_RSA_PKCS_KEY_PAIR_GEN_demo.c` - Demonstrates how to generate RSA key pairs
  - `CKM_EC_KEY_PAIR_GEN_demo.c` - Demonstrates how to generate ECDSA key pairs

- **Encryption**:
  - `CKM_AES_CBC_PAD_demo.c` - Demonstrates AES CBC mode encryption
  - `CKM_AES_CTR_demo.c` - Demonstrates AES Counter mode encryption

- **Object Management**:
  - `C_FindObjects_demo.c` - Demonstrates how to search for objects
  - `C_CreateObject_demo.c` - Demonstrates how to create data objects

### Compiling and Running

The C samples can be compiled using the provided Makefile or manually with GCC. Common make targets include:

- `make all` - Builds all C files
- `make encryption` - Builds all encryption samples
- `make signing` - Builds all signing samples
- `make keygen` - Builds all key generation samples

For detailed instructions on compiling and running the C samples, refer to the [HOW_TO.md](/C_Samples/HOW_TO.md) guide.

## LunaJSP_Samples

The LunaJSP_Samples directory contains Java-based samples that use the Luna Java Security Provider (JSP). These samples demonstrate how to integrate Luna HSMs with Java applications.

### Subdirectories

| Directory | Description | Number of Samples |
|-----------|-------------|-------------------|
| luna_keystore | Samples demonstrating how to use Luna keystore | 8 |
| crypto_operations | Samples demonstrating various cryptographic operations using LunaProvider | 19 |
| object_management | Samples demonstrating how to manage different types of PKCS#11 objects | 16 |
| slot_management | Samples demonstrating various slot management related operations | 4 |
| misc | Samples demonstrating miscellaneous tasks | 5 |

The root directory also contains `LoginLogout.java`, a basic sample demonstrating authentication to the HSM.

### Notable Samples

- **Cryptographic Operations**:
  - `EncryptUsing_AESCBCMode.java` - Demonstrates AES CBC mode encryption
  - `EncryptUsing_AESGCM.java` - Demonstrates AES GCM mode encryption
  - `SignUsing_ECDSA.java` - Demonstrates digital signatures using ECDSA
  - `SignUsing_RSA_PKCS.java` - Demonstrates digital signatures using RSA PKCS

- **Key Management**:
  - Samples in the luna_keystore directory showing keystore operations
  - Object creation and management samples

### Compiling and Running

The Java samples can be compiled using the standard Java compiler (javac). To run the samples, you may need to configure classpath settings to include the Luna JSP libraries.

Example compilation:
```
javac -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar crypto_operations/EncryptUsing_AESCTRMode.java
```

Example execution:
```
java -cp .:/usr/safenet/lunaclient/jsp/lib/LunaProvider.jar crypto_operations/EncryptUsing_AESCTRMode
```

For detailed instructions on compiling and running the Java samples, refer to the [LunaJSP_Samples README](/LunaJSP_Samples/README.md).

## RestAPI_Python

The RestAPI_Python directory contains Python 3 samples that demonstrate how to use the Luna REST API for administrative tasks on Luna Network HSMs.

### Available Samples

| Sample Name | Description |
|-------------|-------------|
| client_list | Displays a list of all registered clients |
| client_show | Displays information about a client |
| client_delete | Deletes a registered client |
| partition_list | Lists all partitions in a Luna Network HSM |
| partition_create | Demonstrates how to create a partition |
| partition_delete | Demonstrates how to delete a partition |
| certificate_based_authentication | Demonstrates certificate-based authentication using Luna REST API |
| user_create | Demonstrates how to create a user |
| user_delete | Demonstrates how to delete a user |
| user_list | Displays a list of all users in a Luna Network HSM |
| user_set_certificate | Demonstrates how to set a certificate to a user |

### Important Cautions

**WARNING AND DISCLAIMER:**
- These samples are for testing purposes only!
- The Luna REST API is intended for HSM-related management tasks only.
- Some of these samples demonstrate the execution of destructive tasks, such as deletion.
- Please do not use these samples if you are unfamiliar with these management tasks.

### Running the Samples

The Python samples can be run directly. Running a sample without arguments will display the correct syntax:

```
./client_list
usage :-
./client_list <HSM_IP_OR_HOST> <appliance_username>
```

For detailed information on using the Python REST API samples, refer to the [RestAPI_Python README](/RestAPI_Python/README.md).

## Browsing the Repository

To explore the full range of samples available:

1. Visit the [repository on GitHub](https://github.com/linuxdevel/luna-samples)
2. Navigate through the directories to find specific samples
3. Each major directory contains its own README file with detailed information
4. Individual samples often contain extensive comments explaining their purpose and usage

For samples organized by functionality rather than language, you can search across the repository for specific keywords (e.g., "AES", "RSA", "ECDSA") to find relevant examples in various languages.

## Further Documentation

Each major sample group contains additional documentation:

- C_Samples: See [HOW_TO.md](/C_Samples/HOW_TO.md) and [README.md](/C_Samples/README.md)
- LunaJSP_Samples: See [README.md](/LunaJSP_Samples/README.md)
- RestAPI_Python: See [README.md](/RestAPI_Python/README.md)

For specialized sample categories, refer to the README files within the specific subdirectories:

- [C_Samples/generating_keys/README.md](/C_Samples/generating_keys/README.md)
- [C_Samples/object_management/README.md](/C_Samples/object_management/README.md)
- [LunaJSP_Samples/crypto_operations/README.md](/LunaJSP_Samples/crypto_operations/README.md)

For general contribution guidelines, see the [Contributing guide](/CONTRIBUTING.md).