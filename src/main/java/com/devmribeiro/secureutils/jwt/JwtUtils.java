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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.devmribeiro.secureutils.SecureUtils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * @author Michael D. Ribeiro
 * @since 1.4
 */
public class JwtUtils {
	Logger log = LoggerFactory.getLogger(JwtUtils.class);

    /**
     * @param username
     * @param rolesList
     * @param jwtPrivateKey
     * @param accessExpirationMs
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public String generateAccessToken(String username, List<String> rolesList, String jwtPrivateKey, int accessExpirationMs) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Jwts
        		.builder()
                .setSubject(username)
                .claim("roles", rolesList)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + accessExpirationMs))
                .signWith(generateJwtKeyEncryption(jwtPrivateKey))
                .compact();
    }

    public PublicKey generateJwtKeyDecryption(String jwtPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	return KeyFactory
    			.getInstance(SecureUtils.RSA_ALGORITHM)
    			.generatePublic(new X509EncodedKeySpec(SecureUtils.base64Decoder(jwtPublicKey.getBytes())));
    }

    public PrivateKey generateJwtKeyEncryption(String jwtPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
        		.getInstance(SecureUtils.RSA_ALGORITHM)
        		.generatePrivate(new PKCS8EncodedKeySpec(SecureUtils.base64Decoder(jwtPrivateKey.getBytes())));
    }

    public boolean validateJwtToken(String authToken, String jwtPublicKey) {
        try {
        	Jwts
        	.parserBuilder()
        	.setSigningKey(generateJwtKeyDecryption(jwtPublicKey))
        	.build()
        	.parse(authToken);
        	return true;
        } catch (MalformedJwtException e) {
        	log.error("Invalid JWT token: {}",  e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}",  e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error("no such algorithm exception");
        } catch (InvalidKeySpecException e) {
            log.error("invalid key exception");
        }
        return false;
    }
}