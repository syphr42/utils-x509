/*
 * Copyright 2011 Gregory P. Moyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.syphr.utils.x509;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import junit.framework.Assert;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class X509UtilsTest
{
    private static final String KEY1_RESOURCE = "/cert/test1.pkcs8";
    private static final String CERT1_RESOURCE = "/cert/test1.x509";

    private static final String CERT2_RESOURCE = "/cert/test2.x509";

    @SuppressWarnings("serial")
    private static final Map<SignatureAlgorithm, String> SIG_KEY1_MESSAGE1_RESOURCE_MAP = new HashMap<SignatureAlgorithm, String>()
    {
        {
            put(SignatureAlgorithm.NONE_RSA, "/sig/sig.none.rsa.data");
            put(SignatureAlgorithm.MD2_RSA, "/sig/sig.md2.rsa.data");
            put(SignatureAlgorithm.MD5_RSA, "/sig/sig.md5.rsa.data");
            put(SignatureAlgorithm.SHA1_RSA, "/sig/sig.sha1.rsa.data");
            put(SignatureAlgorithm.SHA256_RSA, "/sig/sig.sha256.rsa.data");
            put(SignatureAlgorithm.SHA384_RSA, "/sig/sig.sha384.rsa.data");
            put(SignatureAlgorithm.SHA512_RSA, "/sig/sig.sha512.rsa.data");
        }
    };

    private static final String MESSAGE1 = "qwertyuioplkjhgfdsazxcvbnm0987654321";
    private static final String MESSAGE2 = "1234567890mnbvcxzasdfghjklpoiuytrewq";

    @Test
    public void testSign() throws IOException,
                          InvalidKeyException,
                          InvalidKeySpecException,
                          SignatureException
    {
        for (SignatureAlgorithm sigAlg : SignatureAlgorithm.values())
        {
            InputStream key = getKey1();

            try
            {
                byte[] actual = X509Utils.sign(MESSAGE1,
                                               key,
                                               KeyAlgorithm.RSA,
                                               sigAlg);

                InputStream expectedSteam = getSigKey1Message1Expected(sigAlg);
                try
                {
                    byte[] expected = IOUtils.toByteArray(expectedSteam);
                    Assert.assertTrue(sigAlg + " generated bad data",
                                      Arrays.equals(expected, actual));
                }
                finally
                {
                    expectedSteam.close();
                }
            }
            finally
            {
                key.close();
            }
        }
    }

    @Test
    public void testVerifyCorrect() throws IOException,
                                   CertificateException,
                                   InvalidKeyException,
                                   SignatureException,
                                   InvalidKeySpecException
    {
        for (SignatureAlgorithm sigAlg : SignatureAlgorithm.values())
        {
            InputStream key = getKey1();
            InputStream cert = getCert1();

            try
            {
                try
                {
                    Assert.assertTrue(sigAlg + " mismatch",
                                      X509Utils.verify(MESSAGE1,
                                                       X509Utils.sign(MESSAGE1,
                                                                      key,
                                                                      KeyAlgorithm.RSA,
                                                                      sigAlg),
                                                       sigAlg,
                                                       cert));
                }
                finally
                {
                    key.close();
                }
            }
            finally
            {
                cert.close();
            }
        }
    }

    @Test
    public void testVerifyMessageIncorrect() throws IOException,
                                            CertificateException,
                                            InvalidKeyException,
                                            SignatureException,
                                            InvalidKeySpecException
    {
        InputStream key = getKey1();
        InputStream cert = getCert1();

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(MESSAGE2,
                                                    X509Utils.sign(MESSAGE1,
                                                                   key,
                                                                   KeyAlgorithm.RSA,
                                                                   SignatureAlgorithm.MD5_RSA),
                                                    SignatureAlgorithm.MD5_RSA,
                                                    cert));
            }
            finally
            {
                key.close();
            }
        }
        finally
        {
            cert.close();
        }
    }

    @Test
    public void testVerifyKeyIncorrect() throws IOException,
                                        CertificateException,
                                        InvalidKeyException,
                                        SignatureException,
                                        InvalidKeySpecException
    {
        InputStream key = getKey1();
        InputStream cert = getCert2();

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(MESSAGE1,
                                                    X509Utils.sign(MESSAGE1,
                                                                   key,
                                                                   KeyAlgorithm.RSA,
                                                                   SignatureAlgorithm.MD5_RSA),
                                                    SignatureAlgorithm.MD5_RSA,
                                                    cert));
            }
            finally
            {
                key.close();
            }
        }
        finally
        {
            cert.close();
        }
    }

    @Test
    public void testVerifySignatureAlgorithmIncorrect() throws IOException,
                                                       CertificateException,
                                                       InvalidKeyException,
                                                       SignatureException,
                                                       InvalidKeySpecException
    {
        InputStream key = getKey1();
        InputStream cert = getCert2();

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(MESSAGE1,
                                                    X509Utils.sign(MESSAGE1,
                                                                   key,
                                                                   KeyAlgorithm.RSA,
                                                                   SignatureAlgorithm.SHA256_RSA),
                                                    SignatureAlgorithm.MD5_RSA,
                                                    cert));
            }
            finally
            {
                key.close();
            }
        }
        finally
        {
            cert.close();
        }
    }

    private InputStream getKey1() throws IOException
    {
        return getResource(KEY1_RESOURCE);
    }

    private InputStream getCert1() throws IOException
    {
        return getResource(CERT1_RESOURCE);
    }

    private InputStream getCert2() throws IOException
    {
        return getResource(CERT2_RESOURCE);
    }

    private InputStream getSigKey1Message1Expected(SignatureAlgorithm sigAlg) throws IOException
    {
        return getResource(SIG_KEY1_MESSAGE1_RESOURCE_MAP.get(sigAlg));
    }

    private InputStream getResource(String resource) throws IOException
    {
        InputStream is = getClass().getResourceAsStream(resource);

        if (is == null)
        {
            throw new IOException("Unable to find resource: " + resource);
        }

        return is;
    }
}
