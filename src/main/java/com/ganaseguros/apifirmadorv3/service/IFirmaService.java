package com.ganaseguros.apifirmadorv3.service;

import com.ganaseguros.apifirmadorv3.dto.RequestFirmarDto;
import com.ganaseguros.apifirmadorv3.dto.ResponseDto;

public interface IFirmaService {


    public ResponseDto firmar(RequestFirmarDto requestFirmarDto);
    public ResponseDto verificarFirmasPdf(String pdfBase64);


}
