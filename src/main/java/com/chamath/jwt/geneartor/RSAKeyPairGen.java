package com.chamath.jwt.geneartor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.shaded.json.JSONObject;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.UUID;

public class RSAKeyPairGen {

    public static void main(String[] args) throws JOSEException, FileNotFoundException, UnsupportedEncodingException {

        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Map<String, Object> rsaJWKMap=  rsaJWK.toJSONObject();
        JSONObject rsaJWKJSONObj = new JSONObject(rsaJWKMap);
        PrintWriter writer = new PrintWriter("rsa_key.json", "UTF-8");
        writer.write(rsaJWKJSONObj.toJSONString());
        writer.close();
        System.out.println("RSA key saved to rsa_key.json");
    }
}
