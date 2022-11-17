package com.ganaseguros.apifirmadorv3.controller;

import com.ganaseguros.apifirmadorv3.dto.PdfBase64Dto;
import com.ganaseguros.apifirmadorv3.dto.RequestFirmarDto;
import com.ganaseguros.apifirmadorv3.dto.ResponseDto;
import com.ganaseguros.apifirmadorv3.dto.UsuariosFirmantesDto;
import com.ganaseguros.apifirmadorv3.service.IFirmaService;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequestMapping("/api/firma")
public class FirmaController {

    @Autowired
    private IFirmaService iFirmaService;


    @PostMapping("/v1/firmar")
    public ResponseEntity<?> firmar(@RequestBody RequestFirmarDto requestFirmarDto) {
        // SUBIDA DE HOY 17/11/2022
        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.firmar(requestFirmarDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        if(result.getCodigo().equals(ConstDiccionarioMensajeFirma.COD1000))
            response.put("pdfs_firmados", result.getElementoGenerico());
        else
            response.put("log_errores", result.getElementoGenerico());

        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/verificar-firma-pdf")
    public ResponseEntity<?> verificarFirmaPdf(@RequestBody PdfBase64Dto archivoAVerificar) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.verificarFirmasPdf(archivoAVerificar.getPdfBase64());
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("firmas", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/obtiene-informacion-certificado")
    public ResponseEntity<?> obtieneInformacionCertificado(@RequestBody UsuariosFirmantesDto usuariosFirmantesDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.obtieneInformacionCertificado(usuariosFirmantesDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("data_token", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }
}
