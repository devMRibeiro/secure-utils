package com.devmribeiro.secureutils.jwt;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.List;

import com.devmribeiro.secureutils.SecureUtils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * @author Michael D. Ribeiro
 * @since 1.4
 */
public class JWT {
	int accessExpirationMs = 9600000;
    public String generateAccessToken(String userName, List<String> roleArray, String jwtPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Jwts
        		.builder()
                .setSubject(userName)
                .claim("roles", roleArray)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + accessExpirationMs))
                .signWith(generateJwtKeyDecryption(jwtPrivateKey), SignatureAlgorithm.RS256)
                .compact();
    }

    public PublicKey generateJwtKeyDecryption(String jwtPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
        		.getInstance("RSA")
        		.generatePublic(new X509EncodedKeySpec(SecureUtils.base64Decoder(jwtPublicKey.getBytes())));
    }

    public PrivateKey generateJwtKeyEncryption(String jwtPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
        		.getInstance("RSA")
        		.generatePrivate(new PKCS8EncodedKeySpec(SecureUtils.base64Decoder(jwtPrivateKey.getBytes())));
    }

    public boolean validateJwtToken(String authToken, String jwtPublicKey) {
        try {
        	Jwts
        	.parserBuilder()
        	.setSigningKey(generateJwtKeyEncryption(jwtPublicKey))
        	.build()
        	.parseClaimsJws(authToken);
        	return true;

        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token: {}"+ e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: {}"+ e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT token is unsupported: {}"+ e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty: {}"+ e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("no such algorithm exception");
        } catch (InvalidKeySpecException e) {
            System.out.println("invalid key exception");
        }
        return false;
    }
}