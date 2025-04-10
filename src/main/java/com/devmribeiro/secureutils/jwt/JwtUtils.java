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
 * <p>Utility class for generating and validating JWT tokens.</p>
 * 
 * <p>
 * This class provides methods for creating access tokens, 
 * generating encryption and decryption keys, and validating JWTs.
 * </p>
 * 
 * @author Michael D. Ribeiro
 * @since 1.4
 */
public class JwtUtils {
	Logger log = LoggerFactory.getLogger(JwtUtils.class);

	/**
	 * <p>Generates a JWT access token.<p>
     *
     * @param username the username to include in the token's claims
     * @param rolesList a list of roles to include in the token's claims
     * @param jwtPrivateKey the private key used for signing the JWT
     * @param accessExpirationMs the expiration time of the token in milliseconds

     * @return the generated JWT access token as a string
     * 
     * @throws NoSuchAlgorithmException if the specified cryptographic algorithm is not available
     * @throws InvalidKeySpecException if the private key is invalid
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

    /**
     * <p>Generates a public key for JWT decryption.<p>
     * 
     * @param jwtPublicKey the public key in base64-encoded format
     * 
     * @return the generated public key for decrypting the JWT
    
     * @throws NoSuchAlgorithmException if the specified cryptographic algorithm is not available
     * @throws InvalidKeySpecException if the public key is invalid
     */
    public PublicKey generateJwtKeyDecryption(String jwtPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	return KeyFactory
    			.getInstance(SecureUtils.RSA_ALGORITHM)
    			.generatePublic(new X509EncodedKeySpec(SecureUtils.base64Decoder(jwtPublicKey.getBytes())));
    }

    /**
     * <p>Generates a private key for JWT encryption.<p>
     *
     * @param jwtPrivateKey the private key in base64-encoded format
     * 
     * @return the generated private key for signing the JWT
     * 
     * @throws NoSuchAlgorithmException if the specified cryptographic algorithm is not available
     * @throws InvalidKeySpecException if the private key is invalid
     */
    public PrivateKey generateJwtKeyEncryption(String jwtPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
        		.getInstance(SecureUtils.RSA_ALGORITHM)
        		.generatePrivate(new PKCS8EncodedKeySpec(SecureUtils.base64Decoder(jwtPrivateKey.getBytes())));
    }

    /**
     * <p>Validates a JWT token.<p>
     *
     * @param authToken the JWT token to validate
     * @param jwtPublicKey the public key in base64-encoded format used for validation
     * 
     * @return true if the token is valid, false otherwise
     */
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