package project1;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DecryptionFrame extends JFrame {

    private static final String ALGORITHM = "AES";
    private static final String SECRET_KEY = "MySecretKey12345"; 

    private JTextField encryptedInputField;
    private JButton decryptButton;
    private JTextArea resultArea;

    public DecryptionFrame() {
        setTitle("AES Password Decryption");
        setSize(450, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        JLabel label = new JLabel("Enter Encrypted Password (Base64):");
        encryptedInputField = new JTextField(30);
        decryptButton = new JButton("Decrypt");
        resultArea = new JTextArea(4, 35);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setEditable(false);

        add(label);
        add(encryptedInputField);
        add(decryptButton);
        add(new JScrollPane(resultArea));

        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String encryptedText = encryptedInputField.getText().trim();
                if (encryptedText.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Please enter an encrypted password.");
                    return;
                }

                try {
                    String decrypted = decrypt(encryptedText);
                    resultArea.setText("Decrypted Password: " + decrypted);
                } catch (Exception ex) {
                    resultArea.setText("Error: " + ex.getMessage());
                }
            }
        });

        setVisible(true);
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
        new DecryptionFrame();
    }
}
