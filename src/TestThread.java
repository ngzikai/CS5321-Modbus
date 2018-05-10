import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.xml.bind.DatatypeConverter;


class AliceServer {

    public static void sendApc(byte[] sharedSecret){
        try {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            SecretKeySpec aliceAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
            Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aliceCipher.init(Cipher.ENCRYPT_MODE, aliceAesKey, ivspec);

            ServerSocket hmiServer = new ServerSocket(5555);
            ServerSocket bobServer = new ServerSocket(1234);

            Socket hmiSocket = hmiServer.accept();
            Socket bobSocket = bobServer.accept();

            String hmiMessage = "";
            String bobMessage = "";

            String hexCipher = "";

            BufferedReader hmiIn = new BufferedReader(new InputStreamReader(hmiSocket.getInputStream()));
            PrintWriter hmiOut = new PrintWriter(hmiSocket.getOutputStream(), true);
            BufferedReader bobIn = new BufferedReader(new InputStreamReader(bobSocket.getInputStream()));
            PrintWriter bobOut = new PrintWriter(bobSocket.getOutputStream(), true);

            while (true) {
                /**
                 if ((bobMessage = bobIn.readLine()) != null){
                 hmiOut.println(bobMessage);
                 System.out.println("bob: " + bobMessage);
                 }
                 **/
                if ((hmiMessage = hmiIn.readLine()) != null){
                    byte[] ciphertext = aliceCipher.doFinal(hmiMessage.getBytes());
                    hexCipher = DatatypeConverter.printHexBinary(ciphertext);
                    bobOut.println(hexCipher);
                } else {
                    break;
                }
            }

            hmiSocket.close();
            bobSocket.close();
        } catch (Exception e){
            System.out.println(e);
        }
    }


    public static byte[] generateKey() {
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

            ServerSocket bobServer = new ServerSocket(1234);

            Socket connectionSocket = bobServer.accept();

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

            bobServer.close();
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
class multithread implements Runnable {
    private Thread t;
    private String threadName;

    multithread(String name) {
        threadName = name;
        System.out.println("Creating " + threadName);
    }

    public void run(){
        System.out.println("Running " + threadName);
        try {
            for (int i = 4; i > 0; i--){
                System.out.println("Thread: " + threadName + ", " + i);
                Thread.sleep(50);
            }
            AliceServer server = new AliceServer();
            byte[] sharedSecret = server.generateKey();
            server.sendApc(sharedSecret);
        } catch (InterruptedException e){
            System.out.println("Thread " + threadName + " interrupted.");
        }
        System.out.println("Thread " + threadName + " exiting.");
    }

    public void start() {
        System.out.println("Starting " + threadName);
        if (t == null) {
            t = new Thread (this, threadName);
            t.start();
        }
    }

}

public class TestThread {
    public static void main(String[] args) {
        multithread m1 = new multithread("Thread-1");
        m1.start();

        multithread m2 = new multithread("Thread-2");
        m2.start();
    }
}
