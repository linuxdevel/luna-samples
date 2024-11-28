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
	- This sample demonstrates how to generate an RSA-2048 keypair using LunaProvider and use it to sign data.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.
	- This sample uses CKM_RSA_X9_31 mechanism for signing.
	- The CKM_RSA_X9_31 mechanism expects a hash as input, with a 2-byte hash identifier appended to it.
*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.security.MessageDigest;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;
import com.safenetinc.luna.LunaUtils;

public class SignUsing_RSA_X9_31 {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair rsaKeyPair = null;
	private static final int KEY_SIZE = 2048;
	private static final String PROVIDER = "LunaProvider";
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static final String HASH_ALGORITHM = "SHA256"; // Change this to SHA1, SHA224, SHA256, SHA384 or SHA512
	private static byte[] signature = null;
	private static byte[] messageHash = null;


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ SignUsing_RSA_X_509 ]\n");
		System.out.println("Usage-");
		System.out.println("java SignUsing_RSA_X_509 <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java SignUsing_RSA_X_509 myPartition userpin\n");
	}

	// Adds LunaProvider into java security provider List dynamically.
	private static void addLunaProvider() {
		Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
	}

	// generates rsa-2048 keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",PROVIDER);
		keyPairGen.initialize(KEY_SIZE);
		rsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("RSA-2048 keypair generated.");
	}

	// computes sha-256 hash of PLAINTEXT.
	private static void computeHash() throws Exception {
		MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
		digest.update(PLAINTEXT.getBytes());
		messageHash = digest.digest();
	}

	// Returns hash-identiers for RSA_X9_31
	private static byte[] getHashIdentifier() {
		byte hashId[] = new byte[2];
		 switch(HASH_ALGORITHM) {
                        case "SHA1": hashId = LunaUtils.hexStringToByteArray("33cc");
			break;
                        case "SHA224": hashId = LunaUtils.hexStringToByteArray("38cc");
			break;
                        case "SHA256": hashId = LunaUtils.hexStringToByteArray("34cc");
			break;
                        case "SHA384": hashId = LunaUtils.hexStringToByteArray("36cc");
			break;
                        case "SHA512": hashId = LunaUtils.hexStringToByteArray("35cc");
			break;
                }
		return hashId;
	}

	// signs the plaintext using CKM_RSA_X9_31 mechanism.
	private static void signData() throws Exception {
		Signature sign = Signature.getInstance("NONEwithX9_31RSA", PROVIDER);
		sign.initSign(rsaKeyPair.getPrivate());
		sign.update(messageHash);
		sign.update(getHashIdentifier());
		signature = sign.sign();
		System.out.println("Plaintext signed.");
	}

	// verifies the signature.
	private static void verifyData() throws Exception {
		Signature verify = Signature.getInstance("NONEwithX9_31RSA", PROVIDER);
		verify.initVerify(rsaKeyPair.getPublic());
		verify.update(messageHash);
		verify.update(getHashIdentifier());
		if(verify.verify(signature)) {
			System.out.println("Signature verified.");
		} else {
			System.out.println("Signature verification failed.");
		}
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKeyPair();
				computeHash();
				signData();
				verifyData();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

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
