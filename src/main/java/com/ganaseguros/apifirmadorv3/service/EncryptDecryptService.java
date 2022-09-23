package com.ganaseguros.apifirmadorv3.service;

import com.ganaseguros.apifirmadorv3.dto.ResponseDto;
import com.ganaseguros.apifirmadorv3.util.FuncionesGenericos;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.util.Base64;

@Service
public class EncryptDecryptService implements IEncryptDecryptService {

    //referencia
    //https://gist.github.com/jsgao0/52ca6f835a00cccb3cef164f2b9035c1


    // de momento este metodo "encryptMessage" no se usa, ya que el front con la llave publica lo cifra
    /*@Override
    public ResponseDto encryptMessage(String plainText) {
        ResponseDto response = new ResponseDto();
        try {
            byte[] contentBytes = plainText.getBytes();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, FuncionesGenericos.readPublicKey());
            byte[] cipherContent = cipher.doFinal(contentBytes);
            String encoded = Base64.getEncoder().encodeToString(cipherContent);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            response.setElementoGenerico(encoded);

        } catch (Exception e) {
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
        }
        return response;
    }*/

    @Override
    public ResponseDto decryptMessage(String encryptedMessgae) {
        ResponseDto response = new ResponseDto();
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, FuncionesGenericos.readPrivateKey());
            byte[] cipherContentBytes = Base64.getMimeDecoder().decode(encryptedMessgae.getBytes());
            byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
            String decoded = new String(decryptedContent);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            response.setElementoGenerico(decoded);

        } catch (Exception e) {
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
        }
        return response;

    }


}
