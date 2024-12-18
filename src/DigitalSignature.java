import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class DigitalSignature {
    public static byte [] hashFile(String filePath) throws Exception {

        // Message digests are secure one-way hash functions
        // that take arbitrary-sized data and output a fixed-length (512bit = 64 bytes) hash value
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        byte[] fileBytes = FileReader.readFile(filePath); // returns file contents as a byte array
        return messageDigest.digest(fileBytes);  // 512-bit hash
    }

    // this method converts text to Base64
    public static String convertToBase64(String input) {
        byte[] bytes = input.getBytes();
        String convertedText = Base64.getEncoder().encodeToString(bytes);
        return convertedText;
    }

    // converts Base64 to simple text (String line)
    public static String decodeFromBase64(String base64Input) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Input);
        return new String(decodedBytes);
    }

}
