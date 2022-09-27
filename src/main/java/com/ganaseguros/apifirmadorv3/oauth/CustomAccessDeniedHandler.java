package com.ganaseguros.apifirmadorv3.oauth;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");


        Map<String, Object> re = new HashMap<>();
        re.put("codigoMensaje",  ConstDiccionarioMensajeFirma.COD5001);
        re.put("mensaje",ConstDiccionarioMensajeFirma.COD5001_MENSAJE+accessDeniedException.getMessage());



        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write( mapper.writeValueAsString(re));

    }
}
