import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class FileReader {
    public static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Path.of(path));
    }
}
