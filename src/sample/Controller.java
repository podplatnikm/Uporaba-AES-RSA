package sample;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXRadioButton;
import com.jfoenix.controls.JFXToggleButton;
import javafx.event.ActionEvent;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class Controller {
    public JFXToggleButton metodaKriptiranja;
    public AnchorPane apAES;
    public AnchorPane apRSA;
    public Label labelImeDatotekeAES;
    public Label labelImeDatotekeRSA;
    public Label labelImeKljucaAES;
    public JFXToggleButton flagNaloziKljuc;
    public JFXButton bNaloziKljucAES;

    public JFXButton buttonShraniKljucAES;
    public Label labelErrorAES;
    public JFXRadioButton radio128;
    public JFXRadioButton radio192;
    public JFXRadioButton radio256;
    public ToggleGroup AESdolzinaKljuca;
    public Label labelSuccessAES;
    public JFXRadioButton radio2048;
    public JFXRadioButton radio1024;
    public JFXToggleButton switchNaloziKljucaRSA;
    public JFXButton buttonNaloziJavniKljucRSA;
    public JFXButton buttonNaloziZasebniKljucRSA;
    public Label labelImeJavnegaKljucaRSA;
    public Label labelImeZasebnegaKljucaRSA;
    public Label labelErrorRSA;
    public Label labelSuccessRSA;
    public ToggleGroup RSAdolzinaKljuca;
    public JFXButton buttonShraniJavniKljucRSA;
    public JFXButton buttonShraniZasebniKljucRSA;

    private SecretKey secretKeyAES;
    private PublicKey publicKeyRSA;
    private PrivateKey secretKeyRSA;

    private File datotekaAES;
    private File datotekaRSA;
    private File kljucAES;
    private File zasebniKljucRSA;
    private File javniKljucRSA;

    private final FileChooser fileChooserAES = new FileChooser();
    private final FileChooser fileChooserRSA = new FileChooser();
    private final FileChooser fileChooserSaveAES = new FileChooser();
    private final FileChooser fileChooserSaveRSA = new FileChooser();


    public void initialize() {
        odpriOkna();

    }

    public void izbiraMetode(ActionEvent actionEvent) {
        odpriOkna();
    }

    private void odpriOkna() {
        if (metodaKriptiranja.isSelected()) {
            apAES.setDisable(true);
            apRSA.setDisable(false);
        } else {
            apAES.setDisable(false);
            apRSA.setDisable(true);
        }
    }

    public void izberiDatotekoAES(ActionEvent actionEvent) {
        datotekaAES = fileChooserAES.showOpenDialog(new Stage());
        if (datotekaAES != null) {
            labelImeDatotekeAES.setText(datotekaAES.getName());
        } else {
            labelImeDatotekeAES.setText(" ** NAPAKA ** Ni datoteka");
        }
    }


    public void izberiDatotekoRSA(ActionEvent actionEvent) {
        datotekaRSA = fileChooserRSA.showOpenDialog(new Stage());
        if (datotekaRSA != null) {
            labelImeDatotekeRSA.setText(datotekaRSA.getName());
        } else {
            labelImeDatotekeRSA.setText(" ** NAPAKA ** Ni datoteke");
        }
    }

    public void naloziKljuc(ActionEvent actionEvent) {
        if (flagNaloziKljuc.isSelected()) {
            bNaloziKljucAES.setDisable(false);
            labelImeKljucaAES.setDisable(false);
        } else {
            bNaloziKljucAES.setDisable(true);
            labelImeKljucaAES.setDisable(true);
        }
    }

    public void izberiKljucAES(ActionEvent actionEvent) {
        kljucAES = fileChooserAES.showOpenDialog(new Stage());
        if (kljucAES != null) {
            labelImeKljucaAES.setText(kljucAES.getName());
        } else {
            labelImeKljucaAES.setText(" ** NAPAKA ** ");
        }
    }


    public void dekriptirajAES(ActionEvent actionEvent) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        try {
            if (datotekaAES != null) {
                if (flagNaloziKljuc.isSelected() && kljucAES != null) {
                    labelErrorAES.setText("");
                    labelSuccessAES.setText("");

                    ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(kljucAES));
                    secretKeyAES = (SecretKey) inputStream.readObject();

                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, secretKeyAES);

                    FileInputStream fileInputStream = new FileInputStream(datotekaAES);
                    byte[] inputBytes = new byte[(int) datotekaAES.length()];
                    fileInputStream.read(inputBytes);

                    byte[] outputBytes = cipher.doFinal(inputBytes);

                    String pot = datotekaAES.getParent() + "\\";
                    String ime = datotekaAES.getName();
                    String izhodnoIme = ime.substring(0, ime.lastIndexOf('.')) + new Date().getTime() + ".dekriptirano";
                    FileOutputStream outputStream = new FileOutputStream(new File(pot + izhodnoIme));
                    outputStream.write(outputBytes);

                    labelSuccessAES.setText("DEKRIPTIRANJE OK. Shranjeno v datoteko: \n " + izhodnoIme);
                    labelErrorAES.setText("");

                    inputStream.close();
                    outputStream.close();

                    buttonShraniKljucAES.setDisable(false);
                } else {
                    labelErrorAES.setText("NAPAKA: Ni kljuca");
                    labelSuccessAES.setText("");
                }
            } else {
                labelErrorAES.setText("NAPAKA: Ni izbrana datoteka");
                labelSuccessAES.setText("");
            }
        } catch (Exception e) {
            labelErrorAES.setText("NAPAKA: " + e.getMessage());
            labelSuccessAES.setText("");
            e.printStackTrace();
        }
    }

    public void kriptirajAES(ActionEvent actionEvent) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

        boolean uporabiUporabnikovKljuc = false;
        if (flagNaloziKljuc.isSelected()) {
            uporabiUporabnikovKljuc = true;
        }

        try {
            if (datotekaAES != null) {
                if (!uporabiUporabnikovKljuc || kljucAES != null) {
                    labelErrorAES.setText("");
                    labelSuccessAES.setText("");

                    if (!uporabiUporabnikovKljuc) {
                        int dolzinaKljuca;
                        RadioButton radioButton = (RadioButton) AESdolzinaKljuca.getSelectedToggle();
                        dolzinaKljuca = Integer.parseInt(radioButton.getText().substring(0, 3));
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(dolzinaKljuca);
                        secretKeyAES = keyGen.generateKey();
                    } else {
                        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(kljucAES));
                        secretKeyAES = (SecretKey) inputStream.readObject();
                    }

                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeyAES);

                    FileInputStream inputStream = new FileInputStream(datotekaAES);
                    byte[] inputBytes = new byte[(int) datotekaAES.length()];
                    inputStream.read(inputBytes);

                    byte[] outputBytes = cipher.doFinal(inputBytes);

                    String pot = datotekaAES.getParent() + "\\";
                    String ime = datotekaAES.getName();
                    String izhodnoIme = ime.substring(0, ime.lastIndexOf('.')) + new Date().getTime() + ".zakriptirano";
                    FileOutputStream outputStream = new FileOutputStream(new File(pot + izhodnoIme));
                    outputStream.write(outputBytes);

                    labelSuccessAES.setText("KRIPTIRANJE OK. Shranjeno v datoteko: \n " + izhodnoIme);
                    labelErrorAES.setText("");

                    inputStream.close();
                    outputStream.close();

                    buttonShraniKljucAES.setDisable(false);
                } else {
                    labelErrorAES.setText(" NAPAKA: error pri kljucih");
                    labelSuccessAES.setText("");
                }
            } else {
                labelErrorAES.setText("NAPAKA: Ni izbrana datoteka");
                labelSuccessAES.setText("");
            }
        } catch (Exception e) {
            labelErrorAES.setText("NAPAKA: " + e.getMessage());
            labelSuccessAES.setText("");
            e.printStackTrace();
        }
    }


    public void shraniKljucAES(ActionEvent actionEvent) throws IOException {
        fileChooserSaveAES.setInitialFileName("kljucAES.key");
        File file = fileChooserSaveAES.showSaveDialog(new Stage());
        if (file != null) {

            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(file));
            outputStream.writeObject(secretKeyAES);
            outputStream.close();
            /*FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(encoded);
            fileOutputStream.close();*/
            /*FileWriter fileWriter = null;
            try {
                fileWriter = new FileWriter(file, true);
                fileWriter.write(output);
            }catch (Exception e){
                System.out.println("NAPAKA: "+e.getMessage());
                e.printStackTrace();
            }finally {
                if(fileWriter != null){
                    fileWriter.close();
                }

            }*/
        }
    }

    public void odpriNalaganjeKlucevRSA(ActionEvent actionEvent) {
        if (switchNaloziKljucaRSA.isSelected()) {
            buttonNaloziJavniKljucRSA.setDisable(false);
            buttonNaloziZasebniKljucRSA.setDisable(false);
        } else {
            buttonNaloziZasebniKljucRSA.setDisable(true);
            buttonNaloziJavniKljucRSA.setDisable(true);
        }
    }

    public void izberiJavniKljucRSA(ActionEvent actionEvent) {
        javniKljucRSA = fileChooserRSA.showOpenDialog(new Stage());
        if (javniKljucRSA != null) {
            labelImeJavnegaKljucaRSA.setText(javniKljucRSA.getName());
        } else {
            labelImeJavnegaKljucaRSA.setText(" ** NAPAKA ** ");
        }
    }

    public void izberiZasebniKljucRSA(ActionEvent actionEvent) {
        zasebniKljucRSA = fileChooserRSA.showOpenDialog(new Stage());
        if (zasebniKljucRSA != null) {
            labelImeZasebnegaKljucaRSA.setText(zasebniKljucRSA.getName());
        } else {
            labelImeZasebnegaKljucaRSA.setText(" ** NAPAKA ** ");
        }

    }

    public void kriptirajRSA(ActionEvent actionEvent) {
        try {
            if (datotekaRSA != null) {
                if (!switchNaloziKljucaRSA.isSelected() || javniKljucRSA != null) {
                    if (!switchNaloziKljucaRSA.isSelected()) {
                        int dolzinaKljuca;
                        RadioButton radioButton = (RadioButton) RSAdolzinaKljuca.getSelectedToggle();
                        dolzinaKljuca = Integer.parseInt(radioButton.getText().substring(0, 4));
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                        kpg.initialize(dolzinaKljuca);
                        KeyPair keyPair = kpg.generateKeyPair();
                        publicKeyRSA = keyPair.getPublic();
                        secretKeyRSA = keyPair.getPrivate();
                    } else {
                        FileInputStream fis = new FileInputStream(javniKljucRSA);
                        byte[] encodedPublicKey = new byte[(int) javniKljucRSA.length()];
                        fis.read(encodedPublicKey);
                        fis.close();

                        fis = new FileInputStream(zasebniKljucRSA);
                        byte[] encodedPrivateKey = new byte[(int) zasebniKljucRSA.length()];
                        fis.read(encodedPrivateKey);
                        fis.close();

                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
                        publicKeyRSA = keyFactory.generatePublic(publicKeySpec);
                        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
                        secretKeyRSA = keyFactory.generatePrivate(privateKeySpec);
                    }

                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, publicKeyRSA);

                    FileInputStream inputStream = new FileInputStream(datotekaRSA);
                    byte[] inputBytes = new byte[(int) datotekaRSA.length()];
                    inputStream.read(inputBytes);

                    byte[] outputBytes = cipher.doFinal(inputBytes);

                    String pot = datotekaRSA.getParent() + "\\";
                    String ime = datotekaRSA.getName();
                    String izhodnoIme = ime.substring(0, ime.lastIndexOf('.')) + new Date().getTime() + ".zakriptirano";
                    FileOutputStream outputStream = new FileOutputStream(new File(pot + izhodnoIme));
                    outputStream.write(outputBytes);

                    labelSuccessRSA.setText("KRIPTIRANJE OK. Shranjeno v datoteko: \n " + izhodnoIme);
                    labelErrorRSA.setText("");

                    inputStream.close();
                    outputStream.close();

                    buttonShraniJavniKljucRSA.setDisable(false);
                    buttonShraniZasebniKljucRSA.setDisable(false);
                } else {
                    labelErrorRSA.setText("NAPAKA: pri nastavitvah ključev");
                    labelSuccessRSA.setText("");
                }
            } else {
                labelErrorRSA.setText("NAPAKA: Ni izbrana datoteka");
                labelSuccessRSA.setText("");
            }
        } catch (Exception e) {
            labelErrorRSA.setText("NAPAKA: " + e.getMessage());
            labelSuccessRSA.setText("");
            e.printStackTrace();
        }
    }


    public void dekriptirajRSA(ActionEvent actionEvent) {

        try {
            if (switchNaloziKljucaRSA.isSelected() && datotekaRSA != null && zasebniKljucRSA != null) {

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                FileInputStream fis = new FileInputStream(zasebniKljucRSA);
                byte[] encodedPrivateKey = new byte[(int) zasebniKljucRSA.length()];
                fis.read(encodedPrivateKey);
                fis.close();

                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
                secretKeyRSA = keyFactory.generatePrivate(privateKeySpec);

                buttonShraniZasebniKljucRSA.setDisable(false);
                if (javniKljucRSA != null) {
                    fis = new FileInputStream(javniKljucRSA);
                    byte[] encodedPublicKey = new byte[(int) javniKljucRSA.length()];
                    fis.read(encodedPublicKey);
                    fis.close();

                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
                    publicKeyRSA = keyFactory.generatePublic(publicKeySpec);

                    buttonShraniJavniKljucRSA.setDisable(false);
                }

                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, secretKeyRSA);

                FileInputStream inputStream = new FileInputStream(datotekaRSA);
                byte[] inputBytes = new byte[(int) datotekaRSA.length()];
                inputStream.read(inputBytes);

                byte[] outputBytes = cipher.doFinal(inputBytes);

                String pot = datotekaRSA.getParent() + "\\";
                String ime = datotekaRSA.getName();
                String izhodnoIme = ime.substring(0, ime.lastIndexOf('.')) + new Date().getTime() + ".dekriptirano";
                FileOutputStream outputStream = new FileOutputStream(new File(pot + izhodnoIme));
                outputStream.write(outputBytes);

                labelSuccessRSA.setText("DEKRIPTIRANJE OK. Shranjeno v datoteko: \n " + izhodnoIme);
                labelErrorRSA.setText("");

                inputStream.close();
                outputStream.close();


            } else {
                labelErrorRSA.setText("NAPAKA: preverite nastavitve programa");
                labelSuccessRSA.setText("");
            }
        } catch (Exception e) {
            labelErrorRSA.setText("NAPAKA: " + e.getMessage());
            labelSuccessRSA.setText("");
            e.printStackTrace();
        }
    }

    public void shraniJavniKljucRSA(ActionEvent actionEvent) throws IOException {
        fileChooserSaveRSA.setInitialFileName("javniKljucRSA.key");
        File file = fileChooserSaveRSA.showSaveDialog(new Stage());
        if (file != null) {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    publicKeyRSA.getEncoded());
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
        }
    }

    public void shraniZasebniKljucRSA(ActionEvent actionEvent) throws IOException {
        fileChooserSaveRSA.setInitialFileName("zasebniKljucRSA.key");
        File file = fileChooserSaveRSA.showSaveDialog(new Stage());
        if (file != null) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    secretKeyRSA.getEncoded());
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            fos.close();
        }
    }
}
