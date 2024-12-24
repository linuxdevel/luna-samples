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
	- This sample demonstrates how to retrieve an existing RSA PrivateKeyEntry using a KeyStore.
	- The sample searches for the PrivateKeyEntry using its key alias.
	- Once found, the private key is used to sign data using the SHA256withRSA mechanism.
	- The generated signature is then verified using the corresponding public key.

*/


import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.io.ByteArrayInputStream;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class LoadExistingPrivateKey_UsingLunaKeyStore {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static String keyAlias = null;
	private static PrivateKeyEntry signingKey = null;
	private static KeyStore lunaKeyStore = null;
	private static final String PROVIDER = "LunaProvider";
	private static final String PLAINTEXT = "Earth is the third planet of our Solar System.";
	private static byte[] signature = null;


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ LoadExistingPrivateKey_UsingLunaKeyStore ]\n");
		System.out.println("Usage-");
		System.out.println("java LoadExistingPrivateKey_UsingLunaKeyStore <slot_label> <crypto_officer_password> <private_key_entry_alias>\n");
		System.out.println("Example -");
		System.out.println("java LoadExistingPrivateKey_UsingLunaKeyStore myPartition userpin mySigningKey\n");
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
        private static void loadSigningKey() throws Exception {
                signingKey = (PrivateKeyEntry)lunaKeyStore.getEntry(keyAlias, new PasswordProtection("abcd".toCharArray()));
                if(signingKey == null) {
                        System.out.println("Signing Key: " + keyAlias + " not found.");
                        System.exit(1);
                }
                System.out.println("Signing key: "+ keyAlias +" found.");
        }


        // Signs the plaintext using CKM_RSA_PKCS mechanism.
	private static void signData() throws Exception {
		Signature sign = Signature.getInstance("sha256WithRSA", PROVIDER);
		sign.initSign(signingKey.getPrivateKey());
		sign.update(PLAINTEXT.getBytes());
		signature = sign.sign();
		System.out.println("Plaintext signed.");
	}

	// verifies the signature.
	private static void verifyData() throws Exception {
		Signature verify = Signature.getInstance("sha256WithRSA", PROVIDER);
		verify.initVerify(signingKey.getCertificate().getPublicKey());
		verify.update(PLAINTEXT.getBytes());
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
			keyAlias = args[2];
			addLunaProvider();
			loadKeyStore();
			loadSigningKey();
			signData();
			verifyData();
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
