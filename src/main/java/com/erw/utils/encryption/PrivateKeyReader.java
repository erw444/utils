package com.erw.utils.encryption;

import java.security.*;
import java.security.spec.*;
import org.springframework.core.io.Resource;
import org.apache.commons.io.IOUtils;

public class PrivateKeyReader{

    public static PrivateKey get(Resource privateKeyResource) throws Exception{
         byte [] keyBytes = IOUtils.toByteArray(privateKeyResource.getInputStream());

         PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         return keyFactory.generatePrivate(spec);
    }
}


