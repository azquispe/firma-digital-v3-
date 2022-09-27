package com.ganaseguros.apifirmadorv3;

import com.ganaseguros.apifirmadorv3.dto.ResponseDto;
import com.ganaseguros.apifirmadorv3.service.EncryptDecryptService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ApiFirmadorV3ApplicationTests {

	@Autowired
	private EncryptDecryptService encryptDecryptService;

	@Test
	void contextLoads() {
	}

	@Test
	void cifrarPin() {
		String pin = "9133040Nac$";
		ResponseDto resp = encryptDecryptService.encryptMessage(pin);
	}

}
