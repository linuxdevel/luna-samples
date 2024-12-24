        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how to retrieve an existing secret key from a luna partition using KeyStore.
	- It requires a pre-existing AES key in the specified partition.
	- The loaded AES key will then be used to perform encryption.
*/


import java.security.Security;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import java.io.ByteArrayInputStream;
import com.safenetinc.luna.exception.*;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class LoadExistingSecretKey_UsingLunaKeyStore {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static String secretKeyLabel = null;
	private static byte[] encryptedData = null;
	private static byte[] decryptedData = null;
	private static SecretKey encryptionKey = null;
	private static IvParameterSpec ivSpec = null;
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static final String PROVIDER = "LunaProvider";
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final byte[] INITIALIZATION_VECTOR = "1234567812345678".getBytes();
	private static KeyStore lunaKeyStore = null;


	// Prints command usage.
	private static void printUsage() {
		System.out.println(" [ LoadExistingSecretKey_UsingLunaKeyStore ]\n");
		System.out.println("Usage-");
		System.out.println("java LoadExistingSecretKey_UsingLunaKeyStore <slot_label> <crypto_officer_password> <aes_key_label>\n");
		System.out.println("Example -");
		System.out.println("java LoadExistingSecretKey_UsingLunaKeyStore myPartition userpin myAesKey\n");
	}


        // Add LunaProvider to security provider list.
        private static void addLunaProvider() {
                if(Security.getProvider(PROVIDER)==null) {
                        Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
                        System.out.println("LunaProvider added to java.security");
                } else {
                        System.out.println("LunaProvider found in java.security");
                }
        }


	// loads Luna KeyStore (calls C_Login).
        private static void loadKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
                lunaKeyStore = KeyStore.getInstance("Luna");
                lunaKeyStore.load(new ByteArrayInputStream(("tokenlabel:"+slotLabel).getBytes()), slotPassword.toCharArray());
                System.out.println("Luna KeyStore loaded successfully.");
        }


	// loads AES-key.
	private static void loadSecretKey() throws Exception {
		encryptionKey = (SecretKey)lunaKeyStore.getKey(secretKeyLabel, "".toCharArray());
		if(encryptionKey == null) {
			System.out.println("Secret Key: " + secretKeyLabel + " not found.");
			System.exit(1);
		}
		System.out.println("Secret key: "+ secretKeyLabel +" found.");
	}

	// Encrypts plaintext.
	private static void encryptData() throws Exception {
		Cipher encrypt = Cipher.getInstance(ALGORITHM, PROVIDER);
		ivSpec = new IvParameterSpec(INITIALIZATION_VECTOR);
		encrypt.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
		encryptedData = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
	}


	// Decrypts the ciphertext
	private static void decryptData() throws Exception {
		Cipher decrypt = Cipher.getInstance(ALGORITHM, PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);
		decryptedData = decrypt.doFinal(encryptedData);
		System.out.println("Ciphertext decrypted.");
	}


	public static void main(String args[]) {
		try {

			slotLabel = args[0];
			slotPassword = args[1];
			secretKeyLabel = args[2];
			addLunaProvider();
			loadKeyStore();
			loadSecretKey();
			encryptData();
			decryptData();

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
