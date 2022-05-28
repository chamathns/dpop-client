package com.chamath.jwt.geneartor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.util.UUID;

import static com.chamath.jwt.util.DPoPUtils.writeDPoPJWT;

public class DPoPJWTGenerator {

    private static final String JWT_HTU = "https://localhost:9443/oauth2/token";
    private static final String JWT_HTM = "POST";
    private static final String JWT_HTU_RESOURCE = "https://localhost:9443/scim2/Users";
    private static final String JWT_HTM_RESOURCE = "GET";

    public static void main(String[] args) throws JOSEException, ParseException, IOException {

        File jwkJSONFile = new File("/home/chamath/IS/gateway/dpop/jwt-gen/rsa_key.json");
        String jwkJSONString = FileUtils.readFileToString(jwkJSONFile, StandardCharset.UTF_8);

        RSAKey rsaJWK = RSAKey.parse(jwkJSONString);

        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSSigner signer = new RSASSASigner(rsaJWK);

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter profile - token EP(0), resource EP(1): ");
        int profile = sc.nextInt();

        JWTClaimsSet.Builder jwtClaimSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimSetBuilder.jwtID(UUID.randomUUID().toString())
                .issueTime(new Date(new Date().getTime()));

        switch (profile) {
            case 1:
                jwtClaimSetBuilder.claim("htm", JWT_HTM_RESOURCE)
                        .claim("htu", JWT_HTU_RESOURCE);
                break;
            default:
                jwtClaimSetBuilder.claim("htm", JWT_HTM)
                        .claim("htu", JWT_HTU);
        }

        JWTClaimsSet claimsSet = jwtClaimSetBuilder.build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(rsaPublicJWK)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);

        writeDPoPJWT(claimsSet, header, signedJWT);

        String publicKey = computeThumbprintOfKey(rsaPublicJWK);
        System.out.println("cnf jkt: " + publicKey);

        String encodedPublicKey = Base64.getEncoder().encode(publicKey.getBytes(StandardCharsets.UTF_8)).toString();
        System.out.println("encoded cnf jkt: " + encodedPublicKey);
    }

    private static String computeThumbprintOfKey(JWK rsaKey) throws JOSEException {

        return rsaKey.computeThumbprint().toString();
    }
}
