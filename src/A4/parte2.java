package A4;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import static A4.Xifrar.*;


public class parte2 {
    public static void main(String[] args) throws IOException {



        //1.5 A4.Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1
        String mensaje1 = "cifrando y descifrando codigo";
        SecretKey llavesSecreta = keygenKeyGeneration(256);
        byte[] cifrandomensaje = encryptData(llavesSecreta, mensaje1.getBytes());
        byte[] descifrandomensaje = decryptData(llavesSecreta, cifrandomensaje);

        String s = new String(descifrandomensaje);
        System.out.println(s);


        //1.6 A4.Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.
        String mensjae2 = "cifrando y descifrando codigo con contraaseña";
        String contra = "josep";
        SecretKey llavesecreta2 = passwordKeyGeneration(contra, 128);

        byte[] cifrandomensaje2 = encryptData(llavesecreta2, mensjae2.getBytes());
        byte[] descifrandomesaje2 = decryptData(llavesecreta2, cifrandomensaje2);

        String s2 = new String(descifrandomesaje2);
        System.out.println(s2);



        //1.7 Prova alguns dels mètodes que proporciona la classe SecretKey
        System.out.println(llavesSecreta.getEncoded());
        System.out.println(llavesSecreta.getAlgorithm());
        System.out.println(llavesSecreta.getFormat());


        //2
        Path textocifradoplantilla = Paths.get("textamagat");
        Path llavesdeplantilla = Paths.get("clausA4.txt");

        byte[] textoenbytes = Files.readAllBytes(textocifradoplantilla);
        List<String> listadellaves = Files.readAllLines(llavesdeplantilla);

        int i = 0;
        boolean j = false;

        while (!j){

            try {
                SecretKey cp = passwordKeyGeneration(listadellaves.get(i), 128);
                byte[] result = decryptData(cp, textoenbytes);
                System.out.println(result.toString());

                System.out.println(listadellaves.get(i));
                System.out.println(new String(decryptData(cp, textoenbytes)));
                j = true;
            }catch (Exception BadPaddingException){
                i++;
                System.out.println("Contrasenya incorrecta");
            }

        }



        //1.8 Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException
        String mensaje3 = "cifrando y descifrando codigo con contraseña fail";
        String contra3 = "josep2";
        SecretKey llavesecreta3 = passwordKeyGeneration(contra3, 128);

        byte[] cifrandomensaje3 = encryptData(llavesecreta2, mensaje3.getBytes());
        byte[] descifrandomensaje3 = decryptData(llavesecreta3, cifrandomensaje3);

        String s3 = new String(descifrandomensaje3);
        System.out.println(s3);


    }
}