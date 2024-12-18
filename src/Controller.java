import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Controller {

    @FXML
    private Label fileTypeLabel;

    @FXML
    private Label fileSizeLabel;

    @FXML
    private Label fileDateLabel;

    @FXML
    private Label fileModificationLabel;

    @FXML
    private Label fileNameLabel;

    @FXML
    private Label filePathLabel;

    @FXML
    private AnchorPane rootPane;

    @FXML
    private Button podpisButton;

    @FXML
    private Button showOpenText_button;

    @FXML
    private TextArea decodedPublicKey_textArea;

    @FXML
    private TextField openText_textField;


    @FXML
    private TextArea hashedText_textArea;

    @FXML
    private TextArea privateKey_textArea;

    @FXML
    private TextArea publicKey_textArea;

    @FXML
    private TextArea encryptedText_textArea;

    @FXML
    private TextArea filePublicKey_textArea;

    @FXML
    private TextArea checkSignature;

    @FXML
    private TextField username_textField;

    @FXML
    private TextArea signedText_textArea;

    private BigInteger N;
    private BigInteger publicKey;
    private BigInteger privateKey;

    @FXML
    private void selectFile() {
        Stage stage = (Stage) rootPane.getScene().getWindow();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select file with a digital signature");

        File selectedFile = fileChooser.showOpenDialog(stage);
        if (selectedFile != null) {
            try {
                //  podpisBase64 = FileReader.readSignature(selectedFile.getPath());
                showFileDetails(selectedFile);
            } catch (IOException e) {
                clearDetails();
                showErrorDialog("Chyba při načítání souboru", e.getMessage());
            }
        }
    }

    private void clearDetails() {
        fileModificationLabel.setText("-");
        fileDateLabel.setText("-");
        fileSizeLabel.setText("-");
        fileTypeLabel.setText("-");
        filePathLabel.setText("-");
        fileNameLabel.setText("-");
    }

    @FXML
    private void showOpenText() {
        String path = filePathLabel.getText();
        try {
            byte[] openText = FileReader.readFile(path);
            String resultText = new String(openText);
            openText_textField.setText(resultText);
        } catch (IOException e) {
            openText_textField.setText("Chyba při čtení souboru: " + e.getMessage());
        }
    }

    @FXML
    private void hashOpenText() {
        String path = filePathLabel.getText();
        try {
            byte[] hashedText = DigitalSignature.hashFile(path);
            String resultText = Base64.getEncoder().encodeToString(hashedText);
            hashedText_textArea.setText(resultText);
        } catch (Exception e) {
            showErrorDialog("Hash error", "Failed to perform hashing: " + e.getMessage());
        }
    }

    @FXML
    private void handleShowOpenText() {
        showOpenText();
    }

    @FXML
    private void handleHashOPenText() {
        hashOpenText();
    }

    @FXML
    private void savePublicKey() {
        try {
            String publicKey = publicKey_textArea.getText();
            String publicKey_base64 = DigitalSignature.convertToBase64(publicKey);
            String username = username_textField.getText().trim();
            String fileName = username.isEmpty() ? "publicKey.pub" : username + "_publicKey.pub";
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save public key");
            fileChooser.setInitialFileName(fileName);
            File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());

            if (file != null) {
                Files.writeString(file.toPath(), publicKey_base64);
            }
        } catch (IOException e) {
            showErrorDialog("Save Error", "Failed to save public key: " + e.getMessage());

        }
    }

    @FXML
    private void savePrivateKey() {
        try {
            String privateKey1 = privateKey_textArea.getText();
            String privateKey = DigitalSignature.convertToBase64(privateKey1);
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save private key");
            fileChooser.setInitialFileName("privateKey.priv");
            File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());

            if (file != null) {
                Files.writeString(file.toPath(), privateKey);
                // showSuccessDialog("Public Key Saved", "Private key successfully saved to " + file.getAbsolutePath());
            }
        } catch (IOException e) {
            showErrorDialog("Save Error", "Failed to save private key: " + e.getMessage());
        }
    }

    @FXML
    private void initializeKey() {
        BigInteger p = RSA.generate_p_and_q(12);
        BigInteger q = RSA.generate_p_and_q(12);
        N = p.multiply(q);
        publicKey = RSA.find_E(p, q);
        privateKey = RSA.findPrivateKey(publicKey, p, q);
        publicKey_textArea.setText(publicKey.toString());
        privateKey_textArea.setText(privateKey.toString());
    }

    @FXML
    private void signedText() throws Exception {
        String path = filePathLabel.getText();
        byte[] hashedText = DigitalSignature.hashFile(path);
        String hashToEncrypt = Base64.getEncoder().encodeToString(hashedText);
        String privateKey = privateKey_textArea.getText();
        BigInteger privateKey_bigInt = new BigInteger(privateKey);

        List<String> blocks = RSA.splitIntoBlocks(hashToEncrypt);
        StringBuilder encryptedBlocks = new StringBuilder();

        for (String block : blocks) {
            BigInteger blockValue = RSA.textToBigInteger(block);
            BigInteger encryptedBlock = RSA.encrypt(blockValue, N, privateKey_bigInt);
            encryptedBlocks.append(encryptedBlock.toString()).append(" ");
        }

        String encryptedText = encryptedBlocks.toString();
        String result = DigitalSignature.convertToBase64(encryptedText);
        encryptedText_textArea.setText(result);
    }

    @FXML
    private void decrypt_and_check_signature() {
        String signatureText = signedText_textArea.getText();
        String encryptedText = DigitalSignature.decodeFromBase64(signatureText);
        String[] encryptedBlocks = encryptedText.split(" ");
        StringBuilder decryptedMessage = new StringBuilder();
        String publicKey_base64 = filePublicKey_textArea.getText();
        if (publicKey_base64.isEmpty()) {
            showErrorDialog("Error", "Public key is empty.");
            return;
        }

        String publicKey_string = DigitalSignature.decodeFromBase64(publicKey_base64);

        BigInteger publicKey_bigInteger = new BigInteger(publicKey_string);

        for (String encryptedBlock : encryptedBlocks) {
            BigInteger encryptedBlockValue = new BigInteger(encryptedBlock);
            BigInteger decryptedBlockValue = RSA.decrypt(encryptedBlockValue, N, publicKey_bigInteger);
            String decryptedBlock = RSA.bigIntegerToText(decryptedBlockValue);
            decryptedMessage.append(decryptedBlock);
        }
        String result = decryptedMessage.toString();
        decodedPublicKey_textArea.setText(publicKey_bigInteger.toString());
        checkSignature.setText(result);
    }

    @FXML
    private void handleSaveSignature() {
        String fileName = username_textField.getText().trim();
        if (fileName.isEmpty()) {
            showErrorDialog("File name is empty", "Please, enter your username");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save signature");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("ZIP files (*.zip)", "*.zip"));
        fileChooser.setInitialFileName((fileName + ".zip"));
        File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());
        if (file != null) {
            String signedText = encryptedText_textArea.getText();
            saveSignature("temp_output.sign", file, signedText);
        }
    }
    @FXML
    private void saveSignature(String fileName, File zipFile, String text) {
        try {
            File signatureFile = new File(fileName);
            try (FileWriter fileWriter = new FileWriter(signatureFile)) {
                fileWriter.write(text);
            }

            try (FileOutputStream fileOutputStream = new FileOutputStream(zipFile);
                 ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);
                 FileInputStream fileInputStream = new FileInputStream(signatureFile)) {

                ZipEntry zipEntry = new ZipEntry(signatureFile.getName());
                zipOutputStream.putNextEntry(zipEntry);

                byte[] buffer = new byte[1024];
                int length;
                while ((length = fileInputStream.read(buffer)) > 0) {
                    zipOutputStream.write(buffer, 0, length);
                }
            }

            signatureFile.delete();

        } catch (IOException e) {
            showErrorDialog("Error", "Failed to save the signature: " + e.getMessage());
        }
    }


    @FXML
    private void loadPublicKey() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Load Public Key File");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public Key files (*.pub)", "*.pub"));
        File pubKeyFile = fileChooser.showOpenDialog(rootPane.getScene().getWindow());
        if (pubKeyFile != null) {
            try {
                String pubKeyContent = Files.readString(pubKeyFile.toPath());
                filePublicKey_textArea.setText(pubKeyContent);
            } catch (IOException e) {
                showErrorDialog("Error loading Public Key", "Failed to load the public key file: " + e.getMessage());
            }
        }
    }

    private void showErrorDialog(String title, String message) {
        javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                javafx.scene.control.Alert.AlertType.ERROR
        );
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showFileDetails(File file) throws IOException {
        fileNameLabel.setText(file.getName());
        filePathLabel.setText(file.getAbsolutePath());
        String fileName = file.getName();
        int dotIndex = fileName.lastIndexOf('.');
        String extension = fileName.substring(dotIndex + 1);
        fileTypeLabel.setText(extension.toUpperCase());

        long fileSizeBytes = file.length();
        String fileSize = getFileSize(fileSizeBytes);
        fileSizeLabel.setText(fileSize);

        Path path = file.toPath();
        BasicFileAttributes tool = Files.readAttributes(path, BasicFileAttributes.class);

        SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyy HH:mm:ss");

        Date creationTime = new Date(tool.creationTime().toMillis());
        fileDateLabel.setText(dateFormat.format(creationTime));

        Date modificationTime = new Date(tool.lastModifiedTime().toMillis());
        fileModificationLabel.setText(dateFormat.format(modificationTime));
    }

    private String getFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        }
    }

    @FXML
    private void loadZipFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Load ZIP file");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("ZIP files (*.zip)", "*.zip"));
        File zipFile = fileChooser.showOpenDialog(rootPane.getScene().getWindow());
        if (zipFile != null) {
            try {
                File tempDir = new File("temp");
                if (!tempDir.exists()) {
                    tempDir.mkdir();
                }

                try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFile))) {
                    ZipEntry zipEntry;
                    while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                        File extractedFile = new File(tempDir, zipEntry.getName());

                        if (zipEntry.getName().endsWith(".sign")) {
                            try (FileOutputStream fos = new FileOutputStream(extractedFile)) {
                                byte[] buffer = new byte[1024];
                                int length;
                                while ((length = zipInputStream.read(buffer)) > 0) {
                                    fos.write(buffer, 0, length);
                                }
                            }

                            String signContent = Files.readString(extractedFile.toPath());
                            signedText_textArea.setText(signContent);
                            break;
                        }
                    }
                }

            } catch (IOException e) {
                showErrorDialog("Error loading ZIP", "Failed to load or extract ZIP file: " + e.getMessage());
            }
        }
    }
}
