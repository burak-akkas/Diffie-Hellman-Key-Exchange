import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.util.Base64;

/**
 * Created by Burak on 9.01.2016.
 */

// FileManager implementation for Secure File Transfer with "Diffie-Hellman key exchange"
public class FileManager {

    // FileManager singleton instance for Multithread-safe implementation
    private static final FileManager instance = new FileManager();

    // file input stream for reading text files
    private FileInputStream inStream;

    // file output stream for writing text files
    private FileOutputStream outStream;

    // for using Cipher
    private static Cipher cipher;

    // default constructor initializes cipher and secretKey
    protected FileManager() {
        try {
            cipher = Cipher.getInstance("AES");
        } catch(Exception e) {
            System.err.println("Error while getting AES algorithm: " + e);
        }
    }

    // readFile method reads file from given path and returns string of file contents
    public String readFile(String fileName) {

        String fileContent = "";

        try {
            inStream = new FileInputStream(fileName);

            // print read file
            int fileSize = inStream.available();
            for(int i = 0; i < fileSize; i++) {
                fileContent += (char) inStream.read();
            }

        } catch(Exception e) {
            System.err.println("File not found: " + fileName);
        } finally {
            try {
                if(inStream != null) {
                    inStream.close();
                }
            } catch(Exception ex) {
                System.err.println("Error while closing File I/O: " + ex);
            }
        }

        return fileContent;
    }

    // writeFile method creates a file with given name and fills it with given content.
    public void writeFile(String fileName, String fileContent) {
        try {
            outStream = new FileOutputStream(fileName);

            byte[] fileContentBytes = fileContent.getBytes();

            outStream.write(fileContentBytes);

        } catch(Exception e) {
            System.err.println("Error while writing into file " + fileName + ": " + e);
        } finally {
            try {
                if(outStream != null) {
                    outStream.close();
                }
            } catch(Exception ex) {
                System.err.println("Error while closing File I/O: " + ex);
            }
        }
    }

    // splits filename from the path and returns filename string
    public String getFileName(String filePath) {

        String[] split =  filePath.split("\\/");

        return split[split.length - 1];
    }

    // encryptFile method takes plainText and encrypts it with secretKey, returns encrypted string
    public String encryptFile(String plainText, Key secretKey) {
        byte[] plainTextByte = plainText.getBytes();

        String encryptedText = "";

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedByte = cipher.doFinal(plainTextByte);

            Base64.Encoder encoder = Base64.getEncoder();

            encryptedText = encoder.encodeToString(encryptedByte);

        } catch(Exception e) {
            System.err.println("Error while initializing Cipher while encrypting text: " + e);
        }

        return encryptedText;
    }

    // decryptFile method takes encrypted text and decrypts it with secretKey, returns decrypted string
    public String decryptFile(String encryptedText, Key secretKey) {
        Base64.Decoder decoder = Base64.getDecoder();

        byte[] encryptedTextByte = decoder.decode(encryptedText);

        String decryptedText = "";

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

            decryptedText = new String(decryptedByte);
        } catch(Exception e) {
            System.err.println("Error while initializing Cipher while decrypting text: " + e);
        }

        return decryptedText;
    }

    // returns instance of FileManager singleton class.
    public static FileManager getInstance() {
        return instance;
    }
}
