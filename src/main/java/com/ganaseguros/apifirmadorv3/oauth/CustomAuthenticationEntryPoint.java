
package com.ganaseguros.apifirmadorv3.oauth;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.ganaseguros.apifirmadorv3.util.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                         org.springframework.security.core.AuthenticationException e) throws IOException, ServletException {
        httpServletResponse.setContentType("application/json;charset=UTF-8");

        Map<String, Object> response = new HashMap<>();
        response.put("codigoMensaje", ConstDiccionarioMensajeFirma.COD5000);
        response.put("mensaje",ConstDiccionarioMensajeFirma.COD5000_MENSAJE+e.getMessage());


        ObjectMapper mapper = new ObjectMapper();
        httpServletResponse.getWriter().write( mapper.writeValueAsString(response));

    }

}


