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
	- This sample demonstrates how to perform encryption using AES/CTR/NoPadding mode.
	- This sample generates an AES-256 session key.
*/


import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class EncryptUsing_AESCTRMode {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static LunaSlotManager slotManager = null;
	private static byte[] encryptedData = null; // for storing ciphertext.
	private static byte[] decryptedData = null; // for storing decrypted text.
	private static SecretKey encryptionKey = null; // for storing secret key.
	private static IvParameterSpec ivSpec = null; // required for passing initialization vector.
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static final String PROVIDER = "LunaProvider";
	private static final int KEY_SIZE = 256;
	private static final byte[] INITIALIZATION_VECTOR = "1234567812345678".getBytes();


	// Prints command usage.
	private static void printUsage() {
		System.out.println(" [ EncryptUsing_AESCTRMode ]\n");
		System.out.println("Usage-");
		System.out.println("java EncryptUsing_AESCTRMode <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java EncryptUsing_AESCTRMode myPartition userpin\n");
	}


	// Add LunaProvider into security provider list.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}


	// Perform C_Login
	private static void loginToLunaSlot() {
		if(slotManager.findSlotFromLabel(slotLabel)!=-1) {
			slotManager.login(slotLabel, slotPassword);
			System.out.println("Login : SUCCESS.");
		} else {
			System.out.println(slotLabel + " not found.");
			System.exit(1);
		}
	}


	// Generate AES key.
	private static void generateAESKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", PROVIDER);
		keyGenerator.init(KEY_SIZE);
		encryptionKey = keyGenerator.generateKey();
		System.out.println("AES key generated.");
	}


	// Encrypts plaintext.
	private static void encryptData() throws Exception {
		Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding", PROVIDER);
		encrypt.init(Cipher.ENCRYPT_MODE, encryptionKey);
		encryptedData = encrypt.doFinal(PLAINTEXT.getBytes());
		System.out.println("Plaintext encrypted.");
		ivSpec = new IvParameterSpec(encrypt.getIV());
	}


	// Decrypts the ciphertext
	private static void decryptData() throws Exception {
		Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding", PROVIDER);
		decrypt.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);
		decryptedData = decrypt.doFinal(encryptedData);
		System.out.println("Ciphertext decrypted.");
	}


	public static void main(String args[]) {
		try {

			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();
			loginToLunaSlot();
			addLunaProvider();
			generateAESKey();
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
