package com.ganaseguros.apifirmadorv3.service;


import com.ganaseguros.apifirmadorv3.dto.ResponseDto;

public interface IEncryptDecryptService {

        //public ResponseDto encryptMessage(String plainText);
        public ResponseDto decryptMessage(String encryptedMessgae);

}
