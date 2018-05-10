import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

class HmiServer extends Thread{
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private Thread t;
	private String threadName;
	private Socket hmiSock;
	private Socket slaveSock;
	private byte[] sharedSecret;

	HmiServer(String name, byte[] secret, Socket hmi, Socket slave) {
		threadName = name;
		sharedSecret = secret;
		hmiSock = hmi;
		slaveSock = slave;
		System.out.println("Creating " + threadName);
	}

	public void run(){	
		if (threadName.equals("SEND")) {
			System.out.println("This is send la");
			sendApc(sharedSecret, hmiSock, slaveSock);
		} else if (threadName.equals("RECEIVE")){
			System.out.println("THIS IS RECEIVE YAY");
			receiveSlave(sharedSecret, hmiSock, slaveSock);
		}
	}

	public void start() {
		System.out.println("Starting " + threadName);
		if (t == null){
			t = new Thread (this, threadName);
			t.start();
		}
	}

	public static void receiveSlave(byte[] sharedSecret, Socket hmiSocket ,Socket slaveSocket) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    		IvParameterSpec ivspec = new IvParameterSpec(iv);
			SecretKeySpec aliceAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, ivspec);

			String bobMessage = "";
			byte[] decodedHex;

			// BufferedReader hmiIn = new BufferedReader(new InputStreamReader(hmiSocket.getInputStream()));
			PrintWriter hmiOut = new PrintWriter(hmiSocket.getOutputStream(), true);
			BufferedReader bobIn = new BufferedReader(new InputStreamReader(slaveSocket.getInputStream()));
			// PrintWriter bobOut = new PrintWriter(slaveSocket.getOutputStream(), true);

			while (true) {
				
				if ((bobMessage = bobIn.readLine()) != null){
					decodedHex = hexToBytes(bobMessage);
					byte[] recovered = aliceCipher.doFinal(decodedHex);
					String recoveredString = new String(recovered, "UTF-8");
					hmiOut.println(recoveredString);
					// System.out.println("bob: " + bobMessage);
				} else {
					break;
				}
			}

			hmiSocket.close();
			slaveSocket.close();
		} catch (Exception e){
			System.out.println(e);
		}
	}
	
	public static void sendApc(byte[] sharedSecret, Socket hmiSocket ,Socket slaveSocket){
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    		IvParameterSpec ivspec = new IvParameterSpec(iv);
			SecretKeySpec aliceAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aliceCipher.init(Cipher.ENCRYPT_MODE, aliceAesKey, ivspec);

			String hmiMessage = "";
			String hexCipher = "";

			BufferedReader hmiIn = new BufferedReader(new InputStreamReader(hmiSocket.getInputStream()));
			// PrintWriter hmiOut = new PrintWriter(hmiSocket.getOutputStream(), true);
			// BufferedReader bobIn = new BufferedReader(new InputStreamReader(slaveSocket.getInputStream()));
			PrintWriter bobOut = new PrintWriter(slaveSocket.getOutputStream(), true);

			while (true) {
				if ((hmiMessage = hmiIn.readLine()) != null){
					byte[] ciphertext = aliceCipher.doFinal(hmiMessage.getBytes());
					hexCipher = bytesToHex(ciphertext); 
					bobOut.println(hexCipher);	
				} else {
					break;
				}
			}

			hmiSocket.close();
			slaveSocket.close();
		} catch (Exception e){
			System.out.println(e);
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

	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

	public static byte[] hexToBytes(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
}

public class HmiThread {
	public static void main (String args[]) throws Exception{
		byte[] sharedSecret = generateKey();
		System.out.println("Shared Secret: " + bytesToHex(sharedSecret));

		Socket hmiSocket = initSecurePipe(5555);
		Socket slaveSocket = initSecurePipe(1234);
		HmiServer send = new HmiServer("SEND", sharedSecret, hmiSocket, slaveSocket);
		send.start();

		HmiServer receive = new HmiServer("RECEIVE", sharedSecret, hmiSocket, slaveSocket);
		receive.start();
	}

	private static Socket initSecurePipe(int port) throws Exception{
		ServerSocket serversock = new ServerSocket(port);
		return serversock.accept();
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
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

			ServerSocket slaveServer = new ServerSocket(1234);

			Socket connectionSocket = slaveServer.accept();

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
			
			slaveServer.close();
			return aliceSharedSecret;
		} catch (Exception e) {
			System.out.println("Error Generating Shared Secret");
			return null;
		}
	}
}