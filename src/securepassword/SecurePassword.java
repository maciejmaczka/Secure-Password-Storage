/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securepassword;


import java.util.*;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec; 
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import javax.crypto.Cipher;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Maciej
 */
public class SecurePassword {

    /**
     * @param args the command line arguments
     */
    static String  username;
    static String  password;
    
    static String  key;
    
    public static void main(String[] args) {
       
        main_get_args(args);
                
        
        
    }
    
    
    public static void main_get_args(String[] args)
    {
        
        if (args.length == 2)
        {
            
            username = args[0];
            password = args[1];
        
            
        //    System.out.println("User:" + username );
        //    System.out.println("Pass:" + password );
            
            
            crypto_hash (username, password);
            
        }
        
        
        
        
    }
    
    public static byte[] crypto_hash(String username, String password )
    {
   
        byte[] byte_to_be_hashed = (username + password + username).getBytes();
        byte[] byte_key =  (password + username + password).getBytes();
        
        
        try
        {
        
  
           
        
        
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] byte_hash = md5.digest(byte_to_be_hashed);
        byte[] byte_hash_key = md5.digest(byte_key);
        
        
        Cipher aes_cipher =  Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec aes_key_spec = new SecretKeySpec(byte_hash_key, "AES");
        aes_cipher.init(Cipher.ENCRYPT_MODE, aes_key_spec);
        byte[] encrypted = aes_cipher.doFinal(byte_hash);
        
        for (int i = 0 ; i < byte_hash.length ; i++)
        {
            
            System.out.print(String.format("%02x", encrypted[i]));
            
        }
        
       
        return  byte_hash;
                
        
        }
        catch (Exception e)
        {
            
            System.out.println("ERR: " + e.getMessage());
        
        }
        
        return null;
    }
    
    
    
}
