package com.ganaseguros.apifirmadorv3.util;



import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.ganaseguros.apifirmadorv3.dto.CertificadoDto;
import com.ganaseguros.apifirmadorv3.dto.FirmaDto;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class FuncionesFirma {

    public static Boolean downloadSoftoken(String connectStr, String contenedor, String pathDownload, String nameFile) {
        try {

            //https://docs.microsoft.com/es-es/azure/storage/blobs/storage-quickstart-blobs-java?tabs=powershell%2Cenvironment-variable-windows
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectStr).buildClient();
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(contenedor);
            BlobClient blobCertificado = containerClient.getBlobClient(nameFile);
            if(!blobCertificado.exists()){
                return false;
            }
            File p12 = new File(pathDownload + "/" + nameFile);
            blobCertificado.downloadToFile(p12.toString(),true);

            return true;
        } catch (Exception e) {
            return false;
            //throw new RuntimeException(e);
        }
    }
    public static List<String> verificarObservacionEnFirmas(List<FirmaDto> lstFirmas, int nro_documento) {

        List<String> lstMensaje = new ArrayList<>();
        try {
            for (FirmaDto objFirma : lstFirmas) {

                if (!objFirma.isNoModificado()) {
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2010 + " - " + ConstDiccionarioMensajeFirma.COD2010_MENSAJE + ", Usuario: " + objFirma.getCertificado().getNombreSignatario() + " al firmar el Documento Nro: " + nro_documento);
                }
                /*if(!objFirma.isCadenaConfianza()){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2011+" - "+ConstDiccionarioMensajeFirma.COD2011_MENSAJE+", Usuario: "+objFirma.getCertificado().getNombreSignatario() +" al firmar el Documento Nro: "+nro_documento);
                }*/
                if (!objFirma.isFirmadoDuranteVigencia()) {
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2012 + " - " + ConstDiccionarioMensajeFirma.COD2012_MENSAJE + ", Usuario: " + objFirma.getCertificado().getNombreSignatario()  + " al firmar el Documento Nro: " + nro_documento);
                }
                if(!objFirma.isFirmadoAntesRevocacion()){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2013+" - "+ConstDiccionarioMensajeFirma.COD2013_MENSAJE+", Usuario: "+objFirma.getCertificado().getNombreSignatario() +" al firmar el Documento Nro: "+nro_documento);
                }
            }
            return lstMensaje;
        } catch (Exception ex) {
            return new ArrayList<>();
        }
    }
}
