import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by Burak on 9.01.2016.
 */

// ServerProtocol implements threaded server application
public class ServerProtocol implements Runnable {

    // send max 256 bytes per attempt
    private static final int MAXBYTE = 256;

    private Socket clientSocket;
    private Logger threadLogger;
    private String fileName;
    private String fileContent;

    // default constructor for initializing
    public ServerProtocol(Socket socket, Logger logger, String fName, String fContent) {
        this.clientSocket = socket;
        this.threadLogger = logger;
        this.fileName = fName;
        this.fileContent = fContent;
    }

    // thread client handler
    public static void handleClient(Socket clientSocket, Logger threadLogger, String fileName, String fileContent) {

        try {
            DataOutputStream toClient = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream fromClient = new DataInputStream(clientSocket.getInputStream());

            threadLogger.log(Level.INFO, "Sending process started.");

            // server generates p(prime number) and g (prime number's generator)
            // server sends p and g to client
            // server selects a secret number (a)
            // server calculates A=g^a(modp)
            // server sends A to client.
            // server receives B from client.
            // server calculates s=B^a(modp)
            // server now has the secret key

            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024, new SecureRandom());
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

            Random randomGenerator = new Random();

            BigInteger a = new BigInteger(1024, randomGenerator); // secret key a (private) (on server)
            BigInteger p = dhSpec.getP(); // prime number (public) (generated on server)
            BigInteger g = dhSpec.getG(); // primer number generator (public) (generated on server)

            BigInteger A = g.modPow(a, p); // calculated public server key (A=g^a(modp))

            // send prime number
            toClient.writeUTF(p.toString());

            // send prime number generator
            toClient.writeUTF(g.toString());

            // send calculated A
            toClient.writeUTF(A.toString());

            // receive calculated B
            BigInteger B = new BigInteger(fromClient.readUTF());

            // calculate secret key
            BigInteger encryptionKeyServer = B.modPow(a, p);

            System.out.println("Calculated key: " + encryptionKeyServer);

            // generate AES key
            Key key = generateKey(encryptionKeyServer.toByteArray());

            // continue below...
            // send filename first
            toClient.writeUTF(fileName);
            // encrypt file content
            String encryptedFile = FileManager.getInstance().encryptFile(fileContent, key);

            byte[][] split;
            // split file to 256 bytes max
            if((split = chunkArray(encryptedFile.getBytes(), MAXBYTE)) != null) {

                for(int i = 0; i < split.length; i++) {
                    // send split packet
                    toClient.writeUTF(new String(split[i]));
                }
            }

            toClient.writeUTF("");

            toClient.flush();

            threadLogger.log(Level.INFO, "Sending process complete. " + split.length + " total packages sent.");


        } catch(Exception e) {
            threadLogger.log(Level.WARNING, "Error while creating output stream " + e);
        }

    }

    public void run() {
        handleClient(clientSocket, threadLogger, fileName, fileContent);
    }

    public static byte[][] chunkArray(byte[] array, int chunkSize) {
        int numOfChunks = (int)Math.ceil((double)array.length / chunkSize);
        byte[][] output = new byte[numOfChunks][];

        for(int i = 0; i < numOfChunks; ++i) {
            int start = i * chunkSize;
            int length = Math.min(array.length - start, chunkSize);

            byte[] temp = new byte[length];

            System.arraycopy(array, start, temp, 0, length);

            output[i] = temp;
        }

        return output;
    }

    // generates usable SecretKey from given value. In default, user cannot create keys.
    private static Key generateKey(byte[] sharedKey)
    {
        // AES supports 128 bit keys. So, just take first 16 bits of DH generated key.
        byte[] byteKey = new byte[16];
        for(int i = 0; i < 16; i++) {
            byteKey[i] = sharedKey[i];
        }

        // convert given key to AES format
        try {
            Key key = new SecretKeySpec(byteKey, "AES");

            return key;
        } catch(Exception e) {
            System.err.println("Error while generating key: " + e);
        }

        return null;
    }
}
