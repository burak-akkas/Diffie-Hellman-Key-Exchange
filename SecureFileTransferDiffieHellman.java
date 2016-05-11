import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * Created by Burak on 9.01.2016.
 */
public class SecureFileTransferDiffieHellman {
    // send/receive max 256 bytes per attempt
    private static final int MAXBYTE = 256;

    public static void main(String[] args) throws Exception{

        Scanner scan = new Scanner(System.in);

        int selection = 0;

        while(selection != 3) {

            System.out.println("Welcome.");
            System.out.println("Please select operation.");
            System.out.println("1. Send File (to all users will connect)");
            System.out.println("2. Receive File");
            System.out.println("3. Exit");
            System.out.print("> ");

            selection = scan.nextInt();

            switch (selection) {
                case 1:
                    System.out.println("Enter port for listening.");

                    // get port from user
                    int port = scan.nextInt();

                    System.out.println("Enter file path (C:/file.txt) for sending to all clients: ");

                    // get file path from user
                    String filePath = scan.next();

                    // create server socket for listening
                    ServerSocket serverSocket = new ServerSocket(port);

                    // create logger for thread
                    Logger threadLogger = Logger.getLogger("serverLogger");

                    // read selected file into string
                    String fileContent = FileManager.getInstance().readFile(filePath);
                    if(!fileContent.equalsIgnoreCase("")) {
                        // get selected file name
                        String fileName = FileManager.getInstance().getFileName(filePath);

                        System.out.println("Server mode initiated. Serving clients on port " + port);

                        while(true) {
                            Socket clientSocket = serverSocket.accept();

                            // Create new thread to handle new client
                            Thread thread = new Thread(new ServerProtocol(clientSocket, threadLogger, fileName, fileContent));
                            thread.start();
                            threadLogger.info("Created and started new thread " + thread.getName() + " for client.");
                        }
                    } else {
                        System.err.println("File not found.");
                    }

                    break;

                case 2:
                    // get server from user
                    System.out.println("Enter server for receiving.");
                    String server = scan.next();

                    // get port from user
                    System.out.println("Enter port for listening.");
                    int servPort = scan.nextInt();

                    Socket clientSocket = new Socket(server, servPort);

                    DataInputStream fromServer = new DataInputStream(clientSocket.getInputStream());
                    DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());

                    // client receives p(prime number) and g (prime number's generator) from server
                    // client selects a secret number (b)
                    // client calculates B=g^b(modp)
                    // client receives A from the server
                    // client sends B to server.
                    // client calculates s=A^b(modp)
                    // client now has the secret key

                    //---implementation
                    // receive prime number from server
                    BigInteger p = new BigInteger(fromServer.readUTF());
                    // receive prime number generator from server
                    BigInteger g = new BigInteger(fromServer.readUTF());
                    // receive A from server
                    BigInteger A = new BigInteger(fromServer.readUTF());

                    // generate secret b
                    Random randomGenerator = new Random();
                    BigInteger b = new BigInteger(1024, randomGenerator); // secret key b (private) (on client)

                    // calculate public B
                    BigInteger B = g.modPow(b, p); // calculated public client key (B=g^b(modp))

                    // send B to server
                    toServer.writeUTF(B.toString());

                    // calculate secret key
                    BigInteger decryptionKeyClient = A.modPow(b, p);

                    System.out.println("Calculated key: " + decryptionKeyClient);

                    // generate AES key
                    Key key = generateKey(decryptionKeyClient.toByteArray());

                    // continue below...
                    System.out.println("Waiting for file.");

                    try {
                        // read filename from server
                        String fName = fromServer.readUTF();

                        // read encrypted file contents from server
                        String encryptedFile = "";
                        String line;
                        while (!(line = fromServer.readUTF()).equalsIgnoreCase("")) {

                            encryptedFile += line;

                            if (line.isEmpty()) {
                                break;
                            }
                        }

                        // decrypt downloaded file
                        String decryptedFile = FileManager.getInstance().decryptFile(encryptedFile, key);

                        // write to file
                        FileManager.getInstance().writeFile(fName, decryptedFile);

                        // inform user
                        System.out.println("File download complete. Saved in ./" + fName + "\n");

                    } catch (Exception e) {
                        System.err.println("Error while creating/reading server socket: " + e);
                    }

                    break;
                case 3:
                    System.out.println("Bye bye.");
                    break;
                default:
                    System.out.println("Select 1, 2 or 3.");
                    break;
            }

        }

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
