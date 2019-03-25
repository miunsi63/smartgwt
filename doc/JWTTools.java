package com.sds.ssis.jwt;


import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

// This project is licensed under the Apache License 2.0 license. See the LICENSE link for more info.
// https://bitbucket.org/b_c/jose4j.git

public class JWTTools
{
    private String token;
    private String secret;
    private String iss;
    private String errorMessage;
    private String certification = "";
    private String certPath = "com/sds/ssis/jwt";
    
    private JwtClaims jwt;

    public JWTTools ()
    {
    }
    
    public JWTTools (String token, String secret, String iss)
    {
        this.token = token;
        this.secret = secret;
        this.iss = iss;
    }

    public String getIss()
    {
        return iss;
    }

    public void setIss(String iss)
    {
        this.iss = iss;
    }

    public String getToken()
    {
        return token;
    }

    public void setToken(String token)
    {
        this.token = token;
    }

    public String getSecret()
    {
        return secret;
    }

    public void setSecret(String secret)
    {
        this.secret = secret;
    }

    public String getErrorMessage()
    {
        return errorMessage;
    }
    
    public void setCertification(String certification)
    {
        this.certification = certification;
    }

    public void setCertPath(String certPath)
    {
        this.certPath = certPath;
    }

    private boolean createJwtWithCert()
    {
        try
        {
            InputStream inputstream = JWTTools.class.getClassLoader().getResourceAsStream(certPath);
            
            //FileInputStream inputstream = new FileInputStream("C:\\Users\\Uni\\Downloads\\corp3-ssis.p12");
            
            if (inputstream == null)
            {
                System.out.println("Error input");
                return false;
            }

            KeyStore ks = KeyStore.getInstance("PKCS12");

            try
            {
                ks.load(inputstream, "corp3-ssis".toCharArray());
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
            
            PrivateKey privateKey = (PrivateKey) ks.getKey("corp3-ssis", "corp3-ssis".toCharArray());
            Certificate cert = ks.getCertificate("corp3-ssis");
            PublicKey publicKey = cert.getPublicKey();
            // inputStream.close();
            
            AlgorithmConstraints jwsAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256);
            AlgorithmConstraints jweAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
            AlgorithmConstraints jweEncConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime()
                    .setDecryptionKey(privateKey)
                    .setVerificationKey(publicKey)
                    .setJwsAlgorithmConstraints(jwsAlgConstraints)
                    .setJweAlgorithmConstraints(jweAlgConstraints)
                    .setJweContentEncryptionAlgorithmConstraints(jweEncConstraints)
                    .setSkipDefaultAudienceValidation()
                    .build();

            try
            {
                jwt = jwtConsumer.processToClaims(token);
            }
            catch (InvalidJwtException e)
            {
                e.printStackTrace();
                this.errorMessage = e.getMessage();
                
                return false;
            }
            
            return true;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            this.errorMessage = e.getMessage();
            
            return false;
        }
    }

    public String getClaim(String key)
    {
        try
        {
            if (jwt == null)
            {
                if (this.createJwtWithCert() == false)
                {
                    return "FALSE"; 
                }
            }
            
            return (String) jwt.getClaimValue(key);
        }
        catch (Exception e)
        {
            return "FALSE";
        }
    }
    
    public String getClaims()
    {
        try
        {
            if (jwt == null)
            {
                if (this.createJwtWithCert() == false)
                {
                    return "FALSE"; 
                }
            }
            
            return jwt.getRawJson();
        }
        catch (Exception exception)
        {
            this.errorMessage = exception.getMessage();
            return "FALSE";
        }
    }

    
    public static void main(String[] args)
    {
        JWTTools client = new JWTTools();
        
        client.setCertPath ("com/sds/ssis/jwt/corp3-ssis.p12");
        client.setToken("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiQ1V0T3B1Nk9yU0NlaV92d2FnMWVjaE9CR2xuUlRqUVdsNFdwN3BKcXdjNCIsImN0eSI6IkpXVCJ9.Ep2wlmVYur3_WzfFpAbH6apdyB1L_bdaNz1kUut3S1b0yocjLGRlN0E7_hq6aziR1rOT7QS9do6T-nHoM8eLQEd5FTY5yzbXeAYqz9LxYQZUCM95yREGSbk6CPvyRlRFEa9pQe_vII8tPJ_pb-977xBZfs2t6SZ_VIsfvu1om_Lydv1L2gL2VuiGYEYDKfCLUf7u0CaumHvk853kyLff1bwwquht5WoC_6lQzHK7vbXKy3W4PpKHUmOhdLbhtbQxYSeLSrp7knSocTHl6arhVdDlG9KGnw37fAyyRLWQ8I48MsYBDmyKuhprDSaV8eHuSsQINWTNtZWZyQsUxZFaXA.4Gb150TlnxHduliokxvllw.82Gsc2Q8NKfotMscVdlRXA5WLOcBSK-igmUTS9UJRlkrJsM-Oot4rIrvnJDaLEoY2Mrizz9Z98SVyhWkxsKhUKdIDLa970YN0knLcZwtSnru_6i2xzv-ubgIIqYLTEmEZ0ffpfQlnvInds1WUh6pnBmaObxFSokVwLplJw7jlfBrHjhMzw7rTtvDqgOwnyAGFdZ9XTizqepCwWhMPfPC65bOgc-M49Mx3LlXFDQUGUIQAuVhUb0l9_0ko8FvE37ETPEUGWZ9CpWT0ojZ54raWUf38TXTC8EimJksUiOQdpmnzww6VkF4K2uY4KpSLbCNtB2hawyFa1__fJMIIcdYNWT-H4JVEBjugLncN6wXsIx1gGWIaAzZQL6RJ3gYyPZgQyMhfBVJb2e61D26yb9mQSJEWJM-EAj5pzrTdaqySFwUWrDJoNFvoSY31s7-5BPCHCPdA7lEeRqctumqsE943YdQeAQzqZ5MP3g2YwrxYXOH0MdilQyMuk1WGQgOGQQyug2OJA-ghHatNCmNc0lcAYI5R5UG84EzGrKLKXGOVNGLxzfyQtW67LGoCxuSvIftnb59l8OxwwbBmbMjNlMM_LOZ73Z9tb7GmGGlEU37WaUF_8-SIsxBye99z029E7FpYNLKHM53KoTxx8Drmjp7ct4MeeIDVFlgvfHrju4EizlZAS0B1YI3QDdJVcDfy6kEncP-pyCEiZ7fH9FOQuO9Y9zkiac9umpIBJWomNUUVgU02A5Vx8YKH5myAS6LPD_fTIZP75Fnds29yWu05j-e11suEUVXa9PRkOlxPTtWk7r0a0esUK_MvMr3_MXyvFggsKbu6RcVXZiqSqrbZEtv_1onuTb_pBQhJ_4K3mkY24k.ySjcKydHovCwTZh1sOmyPA");

        String issuer = (client.getClaim("iss"));
        
        if (issuer.equals("FALSE"))
        {
            System.out.println(client.getErrorMessage());
        }
        else
        {
            System.out.println(issuer);
        }
    }

}
