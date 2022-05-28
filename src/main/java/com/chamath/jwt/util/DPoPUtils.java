package com.chamath.jwt.util;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

public class DPoPUtils {

    public static void writeDPoPJWT(JWTClaimsSet claimsSet, JWSHeader header, SignedJWT signedJWT)
            throws FileNotFoundException, UnsupportedEncodingException {

        String jwtString = signedJWT.serialize();
        PrintWriter writer = new PrintWriter("dpop_proof_jwt.txt", "UTF-8");
        System.out.println("DPoP proof JWT saved to dpop_proof_jwt.txt");
        System.out.println("header: " + header.toJSONObject());
        System.out.println("payload: " + claimsSet.toJSONObject());
        writer.write(jwtString);
        writer.close();
    }

}
