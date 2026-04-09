import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

public class DigitalSignature {

    public static byte[] hashFile(String filePath) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        byte[] fileBytes = FileReader.readFile(filePath);
        return messageDigest.digest(fileBytes);
    }

    public static String convertToBase64(String input) {
        byte[] bytes = input.getBytes();
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String decodeFromBase64(String base64Input) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Input);
        return new String(decodedBytes);
    }
}
