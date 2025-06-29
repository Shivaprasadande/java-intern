package project1;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class PasswordEncryptDecryptGUI extends JFrame {

    private static final String ALGORITHM = "AES";
    private static final String SECRET_KEY = "MySecretKey12345"; 

    private JTextField passwordField;
    private JButton processButton;
    private JTextArea resultArea;

    public PasswordEncryptDecryptGUI() {
        setTitle("Password Encryptor");
        setSize(450, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        JLabel promptLabel = new JLabel("Enter Password:");
        passwordField = new JTextField(20);
        processButton = new JButton("Encrypt & Decrypt");
        resultArea = new JTextArea(5, 35);
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);

        add(promptLabel);
        add(passwordField);
        add(processButton);
        add(new JScrollPane(resultArea));

        processButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    String inputPassword = passwordField.getText();
                    if (inputPassword.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "Please enter a password.");
                        return;
                    }

                    String encrypted = encrypt(inputPassword);
                    String decrypted = decrypt(encrypted);

                    resultArea.setText("Encrypted: " + encrypted + "\nDecrypted: " + decrypted);
                } catch (Exception ex) {
                    resultArea.setText("Error: " + ex.getMessage());
                }
            }
        });

        setVisible(true);
    }

    public static String encrypt(String password) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedPassword) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        new PasswordEncryptDecryptGUI();
    }
}

