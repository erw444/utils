package com.erw.utils.encryption;
import org.junit.jupiter.api.*;



public class EncryptionServiceTest{

    private String testString = "Test String to encrypt 12!";

    EncryptionService encryptionService = new EncryptionService();

    @Test 
    void encryptWithStringReturnsEncryptedString(){

        String encrypted = encryptionService.encryptAndEncode(testString);

        Assertions.assertNotEquals(testString, encrypted);
    }

    @Test
    void encryptAndThenDecryptReturnsOriginalString(){
        String encrypted = encryptionService.encryptAndEncode(testString);
        
        String decrypted = encryptionService.decrypt(encrypted);

        Assertions.assertNotEquals(testString, encrypted);
        Assertions.assertEquals(testString, decrypted);

    }

    @Test
    void encryptNullValueReturnsNullValue(){
        String encrypted = encryptionService.encryptAndEncode(null);

        Assertions.assertNull(encrypted);
    }

    @Test
    void encryptEmptyValueReturnsEmptyValue(){
        String encrypted = encryptionService.encryptAndEncode("");

        Assertions.assertEquals("", encrypted);
    }

    @Test
    void decryptNullValueReturnsNullValue(){
        String decrypted = encryptionService.decrypt(null);

        Assertions.assertNull(decrypted);
    }

    @Test
    void decryptEmptyValueReturnsEmptyValue(){
        String decrypted = encryptionService.decrypt("");

        Assertions.assertEquals("", decrypted);
    }


}