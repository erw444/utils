package com.erw.utils.encryption;

import java.security.*;
import java.util.Base64;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
class EncryptionService{
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    public EncryptionService(){
        
        try{
            ClassPathResource publicKeyResource = new ClassPathResource("security/public_key.der");
            publicKey = PublicKeyReader.get(publicKeyResource);
        } catch (Exception e){
            logger.error("Failed to read Public Key:" + e);
        }

        try{
            ClassPathResource privateKeyResource = new ClassPathResource("security/private_key.der");
            privateKey = PrivateKeyReader.get(privateKeyResource);
        } catch (Exception e){
            logger.error("Failed to read Private Key:" + e);
        }
    }

    public String encryptAndEncode(String toBeEncrypted){
        if(!StringUtils.isEmpty(toBeEncrypted)){
            byte[] encryptedBytes = doEncryption(toBeEncrypted);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } else {
            return toBeEncrypted;
        }
    }

    private byte[] doEncryption(String toBeEncrypted){
        try{
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipher.update(toBeEncrypted.getBytes());
            byte[] cipherText = cipher.doFinal();

            return cipherText;
        } catch (Exception e) {
            logger.error("Failed to do Encryption: " + e);
            return null;
        }
    }

    public String decrypt(String encryptedEncoded){
        if(!StringUtils.isEmpty(encryptedEncoded)){
            byte[] encrypted = Base64.getDecoder().decode(encryptedEncoded);
            String decrypted = doDecrypt(encrypted);

            return decrypted;
        } else {
            return encryptedEncoded;
        }
    }

    private String doDecrypt(byte[] toBeDecrypted){
        try{
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            cipher.update(toBeDecrypted);
            byte[] cipherText = cipher.doFinal();

            return new String(cipherText);
        } catch (Exception e) {
            logger.error("Failed to do Encryption: " + e);
            return null;
        }
    }
}