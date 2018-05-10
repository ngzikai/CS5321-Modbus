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

class SlaveServer extends Thread {
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private Thread t;
	private String threadName;
	private Socket plcSock;
	private Socket hmiSock;
	private byte[] sharedSecret;

	SlaveServer(String name, byte[] secret, Socket hmi,Socket plc){
		threadName = name;
		sharedSecret = secret;
		hmiSock = hmi;
		plcSock = plc;
		System.out.println("Creating " + threadName);
	}

	public void run() {
		if (threadName.equals("RECEIVE")) {
			System.out.println("This is receive la");
			receiveHmi(sharedSecret, hmiSock, plcSock);
		} else if (threadName.equals("SEND")){
			System.out.println("This is send la");
			sendHmi(sharedSecret, hmiSock, plcSock);
		}
	}

	public void start() {
		System.out.println("Starting " + threadName);
		if(t == null){
			t = new Thread (this, threadName);
			t.start();
		}
	}

	public static void sendHmi(byte[] sharedSecret, Socket hmiSocket, Socket plcSocket){
		try{
			String aliceMessage = "";
			String plcMessage = "";
			String hexCipher = "";

			byte[] decodedHex;

			BufferedReader aliceIn = new BufferedReader(new InputStreamReader(hmiSocket.getInputStream()));
			PrintWriter aliceOut = new PrintWriter(hmiSocket.getOutputStream(), true);
			BufferedReader plcIn = new BufferedReader(new InputStreamReader(plcSocket.getInputStream()));
			PrintWriter plcOut = new PrintWriter(plcSocket.getOutputStream(), true);
        	
        	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    		IvParameterSpec ivspec = new IvParameterSpec(iv);
        	SecretKeySpec bobAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey, ivspec);


			while (true) {
				if ((plcMessage = plcIn.readLine()) != null){
					byte[] ciphertext = bobCipher.doFinal(plcMessage.getBytes());
					hexCipher = bytesToHex(ciphertext);
					aliceOut.println(hexCipher);
				} 
				else {
					break;
				}
			}
			
			hmiSocket.close();
			plcSocket.close();
		} catch (Exception e) {
			System.out.println(e);
		}

	}

	public static void receiveHmi(byte[] sharedSecret, Socket hmiSocket, Socket plcSocket){
		try{
			String aliceMessage = "";
			String plcMessage = "";

			byte[] decodedHex;

			BufferedReader aliceIn = new BufferedReader(new InputStreamReader(hmiSocket.getInputStream()));
			PrintWriter aliceOut = new PrintWriter(hmiSocket.getOutputStream(), true);
			BufferedReader plcIn = new BufferedReader(new InputStreamReader(plcSocket.getInputStream()));
			PrintWriter plcOut = new PrintWriter(plcSocket.getOutputStream(), true);
        	
        	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    		IvParameterSpec ivspec = new IvParameterSpec(iv);
        	SecretKeySpec bobAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			bobCipher.init(Cipher.DECRYPT_MODE, bobAesKey, ivspec);


			while (true) {
				if ((aliceMessage = aliceIn.readLine()) != null){
					decodedHex = hexToBytes(aliceMessage);
					byte[] recovered = bobCipher.doFinal(decodedHex);
					String recoveredString = new String(recovered, "UTF-8");
					plcOut.println(recoveredString);

				}
				/**
				else if ((plcMessage = plcIn.readLine()) != null){
					aliceOut.println(plcMessage);
					System.out.println("plc: " + plcMessage);
				} 
				**/
				else {
					break;
				}
			}
			
			hmiSocket.close();
			plcSocket.close();
		} catch (Exception e) {
			System.out.println(e);
		}

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

public class SlaveThread {
	public static void main(String args[]) throws Exception{
		byte[] sharedSecret = generateKey();
		System.out.println("Shared Secret: " + bytesToHex(sharedSecret));

		Socket plcSocket = initSecurePipe(5556);
		Socket hmiSocket = new Socket("localhost", 1234);

		SlaveServer receive = new SlaveServer("RECEIVE", sharedSecret, hmiSocket,plcSocket);
		receive.start();

		SlaveServer send = new SlaveServer("SEND", sharedSecret, hmiSocket,plcSocket);
		send.start();
	}

	private static Socket initSecurePipe(int port) throws Exception{
		ServerSocket serversock = new ServerSocket(port);
		return serversock.accept();
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	private static byte[] generateKey() {
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
			clientSocket.close();
			
			return bobSharedSecret;
			
		} catch (Exception e) {
			System.out.println("Error Generating Shared Secret!");
			return null;
		}
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
}