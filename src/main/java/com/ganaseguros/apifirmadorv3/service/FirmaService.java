package com.ganaseguros.apifirmadorv3.service;

import com.ganaseguros.apifirmadorv3.dto.*;
import com.ganaseguros.apifirmadorv3.util.FuncionesFirma;
import com.ganaseguros.apifirmadorv3.util.FuncionesGenericos;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import com.ganaseguros.firmar.Firmar;
import com.ganaseguros.firmar.FirmarPdf;
import com.ganaseguros.validar.CertDate;
import com.ganaseguros.validar.Validar;
import com.ganaseguros.validar.ValidarPdf;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.*;


@Service
public class FirmaService implements IFirmaService {

    @Value("${dir.softoken}")
    private String dirSoftoken;



    @Value("${azure.storage.conection}")
    private String connectStr;

    @Value("${azure.storage.namecontent}")
    private String nameContent;

    @Autowired
    IEncryptDecryptService iEncryptDecryptService;

    @Override
    public ResponseDto firmar(RequestFirmarDto requestFirmarDto) {
        ResponseDto result = new ResponseDto();
        List<String> logObservaciones = new ArrayList<>();
        try {
            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (requestFirmarDto.getListaPdf().isEmpty()) {
                logObservaciones.add(ConstDiccionarioMensajeFirma.COD2002 + " - " + ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
            }
            // VALIDAMOS QUE EXISTA USUARIOS FIRMANTES
            if (requestFirmarDto.getListaUsuario().isEmpty()) {
                logObservaciones.add(ConstDiccionarioMensajeFirma.COD2001 + " - " + ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
            }
            for (UsuariosFirmantesDto objUsuarios : requestFirmarDto.getListaUsuario()) {

                // VALIDAMOS SI EL REQUEST TRAE NOMBRE DE USUARIO
                if (objUsuarios.getUserName() == null || objUsuarios.getUserName().trim() == "") {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2001 + " - " + ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
                    continue;
                }

                // DESCARGAMOS SOFTOKEN AL SITIO
                //https://docs.microsoft.com/es-es/azure/storage/blobs/storage-quickstart-blobs-java?tabs=powershell%2Cenvironment-variable-windows
                boolean descargaCorrecta = FuncionesFirma.downloadSoftoken(connectStr, nameContent, dirSoftoken, objUsuarios.getUserName() + ".p12");
                if (!descargaCorrecta) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2003 + " - " + ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                    continue;
                }

                String pathSofToken = dirSoftoken + "/" + objUsuarios.getUserName() + ".p12";
                String vPin = iEncryptDecryptService.decryptMessage(objUsuarios.getPin()).getElementoGenerico().toString();

                List<String> lstArchivosFirmados = new ArrayList<>();
                for (String pdf : requestFirmarDto.getListaPdf()) {

                    //**************
                    byte[] file = Base64.getDecoder().decode(pdf);
                    Firmar firmar = FirmarPdf.getInstance(pathSofToken, "ADSIB", vPin);
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    firmar.firmar(new ByteArrayInputStream(file), out, false);
                    /*Documento documento = new Documento();
                    documento.setBase64(Base64.getEncoder().encodeToString(out.toByteArray()));
                    return documento;*/
                    //*************************
                    lstArchivosFirmados.add(Base64.getEncoder().encodeToString(out.toByteArray()));

                }
                requestFirmarDto.setListaPdf(lstArchivosFirmados);
            }

            int numero_documento = 1;
            for (String base64Firmado : requestFirmarDto.getListaPdf()) {
                ResponseDto resp = this.verificarFirmasPdf(base64Firmado);
                if (!resp.getCodigo().equals(ConstDiccionarioMensajeFirma.COD1000)) {
                    logObservaciones.add(resp.getCodigo() + " - " + resp.getMensaje());
                }
                logObservaciones.addAll(FuncionesFirma.verificarObservacionEnFirmas((List<FirmaDto>) resp.getElementoGenerico(), numero_documento));
                numero_documento++;
            }

        } catch (IOException | GeneralSecurityException ex) {
            logObservaciones.add(ConstDiccionarioMensajeFirma.COD2000 + " - " + ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
        }
        if (!logObservaciones.isEmpty()) {
            result.setMensaje(ConstDiccionarioMensajeFirma.COD2008_MENSAJE);
            result.setCodigo(ConstDiccionarioMensajeFirma.COD2008);
            result.setElementoGenerico(FuncionesGenericos.eliminarDuplicados(logObservaciones));
            return result;
        } else {
            result.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            result.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            result.setElementoGenerico(requestFirmarDto.getListaPdf());
            return result;
        }
    }

    @Override
    public ResponseDto verificarFirmasPdf(String pdfBase64) {
        ResponseDto result = new ResponseDto();
        try {

            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (pdfBase64 == null || pdfBase64.trim() == "") {
                result.setCodigo(ConstDiccionarioMensajeFirma.COD2006);
                result.setMensaje(ConstDiccionarioMensajeFirma.COD2006_MENSAJE);
                return result;
            }
            byte[] decodeFile = Base64.getDecoder().decode(pdfBase64);
            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (decodeFile == null) {
                result.setCodigo(ConstDiccionarioMensajeFirma.COD2006);
                result.setMensaje(ConstDiccionarioMensajeFirma.COD2006_MENSAJE);
                return result;
            }

            //******************************
            byte[] file = Base64.getDecoder().decode(pdfBase64);
            Validar validar = new ValidarPdf(new ByteArrayInputStream(file));
            List<FirmaDto> firmas = new LinkedList<>();
            for (CertDate cert : validar) {
                FirmaDto firma = new FirmaDto(cert.isValid(), cert.isPKI(), cert.isActive(), cert.isOCSP(), cert.isValidAlerted());
                firma.setTimeStamp(cert.getTimeStamp());
                firma.setFechaFirma(cert.getSignDate());
                firma.setCertificado(new CertificadoDto(cert));
                firmas.add(firma);
            }
            //return firmas;
            //****************************************


            result.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            result.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            result.setElementoGenerico(firmas);
            return result;

        } catch (Exception ex) {
            result.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            result.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            return result;
        }

    }
}
