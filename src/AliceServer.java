import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class AliceServer {
	public static void main(String[] args) throws Exception {
		
		byte[] sharedSecret = generateKey();
		
		System.out.println("Shared Secret: " + toHexString(sharedSecret));
	}

	private static byte[] generateKey() {
		/*
		 * Alice creates her own DH key pair with 2048-bit key size
		 */
		try {
			//System.out.println("ALICE: Generate DH keypair ...");
			KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
			aliceKpairGen.initialize(2048);
			KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

			// Alice creates and initializes her DH KeyAgreement object
			//System.out.println("ALICE: Initialization ...");
			KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
			aliceKeyAgree.init(aliceKpair.getPrivate());

			// Alice encodes her public key, and sends it over to Bob.
			byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

			ServerSocket serverSocket = new ServerSocket(1234);

			Socket connectionSocket = serverSocket.accept();

			if (connectionSocket != null) {
				System.out.println("Accepted Bob at " + connectionSocket.getInetAddress());
			}

			DataOutputStream out = new DataOutputStream(connectionSocket.getOutputStream());
			InputStream inStream = connectionSocket.getInputStream();
			byte[] dataBuffer = new byte[10000];

			//System.out.println("Sending over Alice's Public Key");
			out.write(alicePubKeyEnc);

			// Alice Recieves Bob's Public Key
			//System.out.println("Recieving Bob's Public Key");
			int count = inStream.read(dataBuffer);

			byte[] bobPubKeyEnc = new byte[count];

			for (int i = 0; i < bobPubKeyEnc.length; i++) {
				bobPubKeyEnc[i] = dataBuffer[i];
			}

			/*
			 * Alice uses Bob's public key for the first (and only) phase of her version of
			 * the DH protocol. Before she can do so, she has to instantiate a DH public key
			 * from Bob's encoded key material.
			 */
			KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
			PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
			aliceKeyAgree.doPhase(bobPubKey, true);

			/*
			 * At this stage, both Alice and Bob have completed the DH key agreement
			 * protocol. Both generate the (same) shared secret.
			 */
			byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
			
			return aliceSharedSecret;
		} catch (Exception e) {
			System.out.println("Error Generating Shared Secret");
			return null;
		}

	}

	/*
	 * Converts a byte to hex digit and writes to the supplied buffer
	 */
	private static void byte2hex(byte b, StringBuffer buf) {
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		int high = ((b & 0xf0) >> 4);
		int low = (b & 0x0f);
		buf.append(hexChars[high]);
		buf.append(hexChars[low]);
	}

	/*
	 * Converts a byte array to hex string
	 */
	private static String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();
		int len = block.length;
		for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len - 1) {
				buf.append(":");
			}
		}
		return buf.toString();
	}
}