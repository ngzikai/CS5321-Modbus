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

public class BobServer {
	public static void main(String args[]) throws Exception {
		byte[] sharedSecret = generateKey();
		
		System.out.println("Shared Secret: " + toHexString(sharedSecret));
	}
	
	public static byte[] generateKey() {
		try {
			// Connecting to Alice's server
			Socket clientSocket = new Socket("localhost", 1234);

			DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

			InputStream inStream = clientSocket.getInputStream();
			byte[] dataBuffer = new byte[10000];
			int count = inStream.read(dataBuffer);

			byte[] alicePubKeyEnc = new byte[count];

			for (int i = 0; i < alicePubKeyEnc.length; i++) {
				alicePubKeyEnc[i] = dataBuffer[i];
			}

			//System.out.println("Recieved Alice's Key!");

			/*
			 * Bob receives Alice's public key in encoded format. He instantiates a DH
			 * public key from the encoded key material.
			 */
			KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

			PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

			/*
			 * Bob gets the DH parameters associated with Alice's public key. He must use
			 * the same parameters when he generates his own key pair.
			 */

			DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey) alicePubKey).getParams();

			// Bob creates his own DH key pair
			//System.out.println("BOB: Generate DH keypair ...");
			KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
			bobKpairGen.initialize(dhParamFromAlicePubKey);
			KeyPair bobKpair = bobKpairGen.generateKeyPair();

			// Bob creates and initializes his DH KeyAgreement object
			//System.out.println("BOB: Initialization ...");
			KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
			bobKeyAgree.init(bobKpair.getPrivate());

			// Bob encodes his public key, and sends it over to Alice.
			byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

			//System.out.println("Sending over Bob's Key");
			out.write(bobPubKeyEnc);

			/*
			 * Bob uses Alice's public key for the first (and only) phase of his version of
			 * the DH protocol.
			 */
			bobKeyAgree.doPhase(alicePubKey, true);

			/*
			 * At this stage, both Alice and Bob have completed the DH key agreement
			 * protocol. Both generate the (same) shared secret.
			 */

			byte[] bobSharedSecret = bobKeyAgree.generateSecret();
			
			return bobSharedSecret;
			
		} catch (Exception e) {
			System.out.println("Error Generating Shared Secret!");
			return null;
		}
	}
	
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
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
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
