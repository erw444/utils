package com.erw.utils.encryption;

import java.security.*;
import java.security.spec.*;
import org.springframework.core.io.Resource;
import org.apache.commons.io.IOUtils;

public class PublicKeyReader{

    public static PublicKey get(Resource publicKeyResource) throws Exception{
         byte [] keyBytes = IOUtils.toByteArray(publicKeyResource.getInputStream());

         X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         return keyFactory.generatePublic(spec);
    }
}


