package com.ganaseguros.apifirmadorv3.service;

import com.ganaseguros.apifirmadorv3.dto.*;
import com.ganaseguros.apifirmadorv3.util.FuncionesFirma;
import com.ganaseguros.apifirmadorv3.util.FuncionesGenericos;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import com.ganaseguros.firmar.Firmar;
import com.ganaseguros.firmar.FirmarPdf;
import com.ganaseguros.token.Token;
import com.ganaseguros.token.TokenHsmCloud;
import com.ganaseguros.token.TokenPKCS12;
import com.ganaseguros.validar.CertDate;
import com.ganaseguros.validar.DatosCertificado;
import com.ganaseguros.validar.Validar;
import com.ganaseguros.validar.ValidarPdf;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
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
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2003 + " - " + ConstDiccionarioMensajeFirma.COD2003_MENSAJE+", para el usuario: "+objUsuarios.getUserName());
                    continue;
                }
                // VERIICFAR QUE EL CIFRADO EL PIN SEA CORRECTO
                String pathSofToken = dirSoftoken + "/" + objUsuarios.getUserName() + ".p12";
                ResponseDto resp = iEncryptDecryptService.decryptMessage(objUsuarios.getPin());
                if (!resp.getCodigo().equals(ConstDiccionarioMensajeFirma.COD1000)) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2004 + " - " + ConstDiccionarioMensajeFirma.COD2004_MENSAJE+", para el usuario: "+objUsuarios.getUserName());
                    continue;
                }

                // VERIFICAR QUE EL PIN SEA AL QUE PERTENECE AL SOFTOKEN
                String vPin = resp.getElementoGenerico().toString();
                Token token = new TokenPKCS12(pathSofToken);
                try {
                    token.iniciar(vPin);
                } catch (Exception ex) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2004 + " - " + ConstDiccionarioMensajeFirma.COD2004_MENSAJE+", para el usuario: "+objUsuarios.getUserName());
                    continue;
                }


                List<String> lstArchivosFirmados = new ArrayList<>();
                for (String pdf : requestFirmarDto.getListaPdf()) {

                    //VALIDAMOS SI EL REQUEST TRAE BASE 64 (DOCUMENTOS)
                    if (pdf == null || pdf.trim() == "") {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2002 + " - " + ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
                        continue;
                    }

                    //**************
                    //VERIFICAMOS QUE EL ARCHIVO TENGA UN FORMATO CORRECTO DE BASE64
                    byte[] file = null;
                    try {
                        file = Base64.getDecoder().decode(pdf);
                    } catch (Exception ex) {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2005 + " - " + ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                        continue;
                    }

                    //VERIFICAMOS QUE EL FIRMADO SEA CORRECTO
                    try {
                        Firmar firmar = FirmarPdf.getInstance(pathSofToken, "ADSIB", vPin);
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        firmar.firmar(new ByteArrayInputStream(file), out, false, token);
                        //*************************
                        lstArchivosFirmados.add(Base64.getEncoder().encodeToString(out.toByteArray()));
                    } catch (Exception ex) {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2007 + " - " + ConstDiccionarioMensajeFirma.COD2007_MENSAJE);
                        continue;
                    }

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

        } catch (Exception ex) {
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
            //byte[] file = Base64.getDecoder().decode(pdfBase64);
            Validar validar = new ValidarPdf(new ByteArrayInputStream(decodeFile));
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

    //ESTE METODO NO ESTABA EN EL SATELITE DE ADSIB, ESTE METODO ES COPIA DE JACUBITOS (JACUBITOS BAJADO DE GOTLAB POR EL MES DE ABRIL DEL 2022)
    @Override
    public ResponseDto obtieneInformacionCertificado(UsuariosFirmantesDto usuariosFirmantesDto) {
        ResponseDto response = new ResponseDto();
        try {

            // DESCARGAMOS SOFTOKEN AL SITIO
            //https://docs.microsoft.com/es-es/azure/storage/blobs/storage-quickstart-blobs-java?tabs=powershell%2Cenvironment-variable-windows
            boolean descargaCorrecta = FuncionesFirma.downloadSoftoken(connectStr, nameContent, dirSoftoken, usuariosFirmantesDto.getUserName() + ".p12");
            if (!descargaCorrecta) {
                //logObservaciones.add(ConstDiccionarioMensajeFirma.COD2003 + " - " + ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE+", para el usuario: "+usuariosFirmantesDto.getUserName());
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
                return response;
            }

            //String pathSofToken = dirSoftoken + "/" + usuariosFirmantesDto.getUserName() + "/softoken.p12";
            String pathSofToken = dirSoftoken + "/" + usuariosFirmantesDto.getUserName() + ".p12";
            File file = new File(pathSofToken);
            // VALIDAMOS SI EXISTE CARPETA DEL USUARIO
            if (!file.exists()) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE+", para el usuario: "+usuariosFirmantesDto.getUserName());
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
                return response;
            }


            // VALIDADMOS PIN CORRECTO
            Token token = new TokenPKCS12(pathSofToken);
            try {
                String vPin = iEncryptDecryptService.decryptMessage(usuariosFirmantesDto.getPin()).getElementoGenerico().toString(); // Decifra el PIN
                token.iniciar(vPin);
            } catch (Exception ex) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE+", para el usuario: "+usuariosFirmantesDto.getUserName());
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                return response;
            }
            List<String> llaves = token.listarIdentificadorClaves();
            try {

                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                InputStream is = getClass().getClassLoader().getResourceAsStream("firmadigital_bo.crt");
                List<X509Certificate> intermediates = (List<X509Certificate>) fact.generateCertificates(is);

                JSONObject data_token = new JSONObject();
                data_token.put("certificates", llaves.size());
                data_token.put("data", new JSONArray());
                for (int i = 0; i < llaves.size(); i++) {
                    JSONObject key = new JSONObject();
                    key.put("tipo", "PRIMARY_KEY");
                    key.put("tipo_desc", "Clave Privada");
                    key.put("alias", llaves.get(i));
                    key.put("id", llaves.get(i));
                    X509Certificate cert = token.obtenerCertificado(llaves.get(i));
                    DatosCertificado datos = new DatosCertificado(cert);
                    key.put("tiene_certificado", cert != null);
                    ((JSONArray) data_token.get("data")).put(key);
                    if (key.getBoolean("tiene_certificado")) {
                        JSONObject x509 = new JSONObject();
                        x509.put("tipo", "X509_CERTIFICATE");
                        x509.put("tipo_desc", "Certificado");
                        x509.put("adsib", false);
                        for (X509Certificate intermediate : intermediates) {
                            try {
                                cert.verify(intermediate.getPublicKey());
                                x509.put("adsib", true);
                                break;
                            } catch (GeneralSecurityException ex) {
                            }
                        }
                        x509.put("serialNumber", cert.getSerialNumber().toString(16));
                        x509.put("alias", llaves.get(i));
                        x509.put("id", llaves.get(i));
                        String pem = "-----BEGIN CERTIFICATE-----\n";
                        pem += Base64.getEncoder().encodeToString(cert.getEncoded());
                        pem += "\n-----END CERTIFICATE-----";
                        x509.put("pem", pem);
                        x509.put("validez", new JSONObject());
                        ((JSONObject) x509.get("validez")).put("desde", dateFormat.format(datos.getInicioValidez()));
                        ((JSONObject) x509.get("validez")).put("hasta", dateFormat.format(datos.getFinValidez()));
                        x509.put("titular", new JSONObject());
                        ((JSONObject) x509.get("titular")).put("dnQualifier", datos.getTipoDocumentoSubject());
                        ((JSONObject) x509.get("titular")).put("uidNumber", datos.getNumeroDocumentoSubject());
                        ((JSONObject) x509.get("titular")).put("UID", datos.getComplementoSubject());
                        ((JSONObject) x509.get("titular")).put("CN", datos.getNombreComunSubject());
                        ((JSONObject) x509.get("titular")).put("T", datos.getCargoSubject());
                        ((JSONObject) x509.get("titular")).put("O", datos.getOrganizacionSubject());
                        ((JSONObject) x509.get("titular")).put("OU", datos.getUnidadOrganizacionalSubject());
                        ((JSONObject) x509.get("titular")).put("EmailAddress", datos.getCorreoSubject());
                        ((JSONObject) x509.get("titular")).put("description", datos.getDescripcionSubject());
                        x509.put("common_name", datos.getNombreComunSubject());
                        x509.put("emisor", new JSONObject());
                        ((JSONObject) x509.get("emisor")).put("CN", datos.getNombreComunIssuer());
                        ((JSONObject) x509.get("emisor")).put("O", datos.getOrganizacionIssuer());
                        ((JSONArray) data_token.get("data")).put(x509);
                    }
                }
                data_token.put("private_keys", llaves.size());

                response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
                response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);


                Map<String, Object> map = new Gson()
                        .fromJson(data_token.toString(), new TypeToken<HashMap<String, Object>>() {
                        }.getType());

                response.setElementoGenerico(map);


            } catch (GeneralSecurityException ex) {
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            }

            token.salir();
            return response;

        } catch (Exception ex) {
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            return response;
        }
    }

}
