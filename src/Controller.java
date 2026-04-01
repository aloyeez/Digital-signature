import javafx.fxml.FXML;
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

    @FXML private Label fileTypeLabel;
    @FXML private Label fileSizeLabel;
    @FXML private Label fileDateLabel;
    @FXML private Label fileModificationLabel;
    @FXML private Label fileNameLabel;
    @FXML private Label filePathLabel;
    @FXML private AnchorPane rootPane;
    @FXML private TextArea decodedPublicKey_textArea;
    @FXML private TextField openText_textField;
    @FXML private TextArea hashedText_textArea;
    @FXML private TextArea privateKey_textArea;
    @FXML private TextArea publicKey_textArea;
    @FXML private TextArea encryptedText_textArea;
    @FXML private TextArea filePublicKey_textArea;
    @FXML private TextArea checkSignature;
    @FXML private TextField username_textField;
    @FXML private TextArea signedText_textArea;

    private BigInteger N;
    private BigInteger publicKey;
    private BigInteger privateKey;

    @FXML
    private void selectFile() {
        Stage stage = (Stage) rootPane.getScene().getWindow();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select file to sign");

        File selectedFile = fileChooser.showOpenDialog(stage);
        if (selectedFile != null) {
            try {
                showFileDetails(selectedFile);
            } catch (IOException e) {
                clearDetails();
                showErrorDialog("Error loading file", e.getMessage());
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
    private void handleShowOpenText() {
        String path = filePathLabel.getText();
        try {
            byte[] openText = FileReader.readFile(path);
            openText_textField.setText(new String(openText));
        } catch (IOException e) {
            openText_textField.setText("Error reading file: " + e.getMessage());
        }
    }

    @FXML
    private void handleHashOpenText() {
        String path = filePathLabel.getText();
        try {
            byte[] hashedText = DigitalSignature.hashFile(path);
            hashedText_textArea.setText(Base64.getEncoder().encodeToString(hashedText));
        } catch (Exception e) {
            showErrorDialog("Hash error", "Failed to perform hashing: " + e.getMessage());
        }
    }

    @FXML
    private void savePublicKey() {
        try {
            String publicKeyBase64 = DigitalSignature.convertToBase64(publicKey_textArea.getText());
            String username = username_textField.getText().trim();
            String fileName = username.isEmpty() ? "publicKey.pub" : username + "_publicKey.pub";

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save public key");
            fileChooser.setInitialFileName(fileName);
            File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());

            if (file != null) {
                Files.writeString(file.toPath(), publicKeyBase64);
            }
        } catch (IOException e) {
            showErrorDialog("Save error", "Failed to save public key: " + e.getMessage());
        }
    }

    @FXML
    private void savePrivateKey() {
        try {
            String privateKeyBase64 = DigitalSignature.convertToBase64(privateKey_textArea.getText());

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save private key");
            fileChooser.setInitialFileName("privateKey.priv");
            File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());

            if (file != null) {
                Files.writeString(file.toPath(), privateKeyBase64);
            }
        } catch (IOException e) {
            showErrorDialog("Save error", "Failed to save private key: " + e.getMessage());
        }
    }

    @FXML
    private void initializeKey() {
        BigInteger p = RSA.generatePrime(12);
        BigInteger q = RSA.generatePrime(12);
        N = p.multiply(q);
        publicKey = RSA.findPublicExponent(p, q);
        privateKey = RSA.findPrivateKey(publicKey, p, q);
        publicKey_textArea.setText(publicKey + "|" + N);
        privateKey_textArea.setText(privateKey + "|" + N);
    }

    @FXML
    private void signedText() throws Exception {
        String path = filePathLabel.getText();
        byte[] hashedText = DigitalSignature.hashFile(path);
        String hashToEncrypt = Base64.getEncoder().encodeToString(hashedText);
        BigInteger privateKeyBigInt = new BigInteger(privateKey_textArea.getText().split("\\|")[0]);

        List<String> blocks = RSA.splitIntoBlocks(hashToEncrypt);
        StringBuilder encryptedBlocks = new StringBuilder();

        for (String block : blocks) {
            BigInteger blockValue = RSA.textToBigInteger(block);
            BigInteger encryptedBlock = RSA.encrypt(blockValue, N, privateKeyBigInt);
            encryptedBlocks.append(encryptedBlock.toString()).append(" ");
        }

        encryptedText_textArea.setText(DigitalSignature.convertToBase64(encryptedBlocks.toString()));
    }

    @FXML
    private void decrypt_and_check_signature() {
        String publicKeyBase64 = filePublicKey_textArea.getText();
        if (publicKeyBase64.isEmpty()) {
            showErrorDialog("Error", "Public key is empty.");
            return;
        }

        String publicKeyRaw = DigitalSignature.decodeFromBase64(publicKeyBase64);
        String[] parts = publicKeyRaw.split("\\|");
        if (parts.length != 2) {
            showErrorDialog("Error", "Invalid public key format. Expected 'e|N'.");
            return;
        }

        BigInteger publicKeyBigInt = new BigInteger(parts[0]);
        BigInteger nFromKey = new BigInteger(parts[1]);

        String encryptedText = DigitalSignature.decodeFromBase64(signedText_textArea.getText());
        String[] encryptedBlocks = encryptedText.split(" ");
        StringBuilder decryptedMessage = new StringBuilder();

        for (String encryptedBlock : encryptedBlocks) {
            if (encryptedBlock.isEmpty()) continue;
            BigInteger encryptedBlockValue = new BigInteger(encryptedBlock);
            BigInteger decryptedBlockValue = RSA.decrypt(encryptedBlockValue, nFromKey, publicKeyBigInt);
            decryptedMessage.append(RSA.bigIntegerToText(decryptedBlockValue));
        }

        decodedPublicKey_textArea.setText(publicKeyBigInt.toString());
        checkSignature.setText(decryptedMessage.toString());
    }

    @FXML
    private void handleSaveSignature() {
        String fileName = username_textField.getText().trim();
        if (fileName.isEmpty()) {
            showErrorDialog("Username required", "Please enter your username before saving.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save signature");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("ZIP files (*.zip)", "*.zip"));
        fileChooser.setInitialFileName(fileName + ".zip");
        File file = fileChooser.showSaveDialog(rootPane.getScene().getWindow());

        if (file != null) {
            saveSignatureToZip("temp_output.sign", file, encryptedText_textArea.getText());
        }
    }

    private void saveSignatureToZip(String signFileName, File zipFile, String text) {
        try {
            File signatureFile = new File(signFileName);
            try (FileWriter fileWriter = new FileWriter(signatureFile)) {
                fileWriter.write(text);
            }

            try (FileOutputStream fos = new FileOutputStream(zipFile);
                 ZipOutputStream zipOut = new ZipOutputStream(fos);
                 FileInputStream fis = new FileInputStream(signatureFile)) {

                zipOut.putNextEntry(new ZipEntry(signatureFile.getName()));
                byte[] buffer = new byte[1024];
                int length;
                while ((length = fis.read(buffer)) > 0) {
                    zipOut.write(buffer, 0, length);
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
        fileChooser.setTitle("Load public key file");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public key files (*.pub)", "*.pub"));
        File pubKeyFile = fileChooser.showOpenDialog(rootPane.getScene().getWindow());

        if (pubKeyFile != null) {
            try {
                filePublicKey_textArea.setText(Files.readString(pubKeyFile.toPath()));
            } catch (IOException e) {
                showErrorDialog("Error loading public key", "Failed to load the public key file: " + e.getMessage());
            }
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

                try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFile))) {
                    ZipEntry zipEntry;
                    while ((zipEntry = zipIn.getNextEntry()) != null) {
                        if (zipEntry.getName().endsWith(".sign")) {
                            File extractedFile = new File(tempDir, zipEntry.getName());
                            try (FileOutputStream fos = new FileOutputStream(extractedFile)) {
                                byte[] buffer = new byte[1024];
                                int length;
                                while ((length = zipIn.read(buffer)) > 0) {
                                    fos.write(buffer, 0, length);
                                }
                            }
                            signedText_textArea.setText(Files.readString(extractedFile.toPath()));
                            break;
                        }
                    }
                }

            } catch (IOException e) {
                showErrorDialog("Error loading ZIP", "Failed to load or extract ZIP file: " + e.getMessage());
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
        fileTypeLabel.setText(dotIndex >= 0 ? fileName.substring(dotIndex + 1).toUpperCase() : "—");

        fileSizeLabel.setText(getFileSize(file.length()));

        BasicFileAttributes attrs = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
        fileDateLabel.setText(dateFormat.format(new Date(attrs.creationTime().toMillis())));
        fileModificationLabel.setText(dateFormat.format(new Date(attrs.lastModifiedTime().toMillis())));
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
}
