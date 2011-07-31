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
    private static final String RSA_KEY1_RESOURCE = "/cert/rsa1.pkcs8";
    private static final String RSA_CERT1_RESOURCE = "/cert/rsa1.x509";

    private static final String RSA_CERT2_RESOURCE = "/cert/rsa2.x509";

    private static final String DSA_KEY1_RESOURCE = "/cert/dsa1.pkcs8";
    private static final String DSA_CERT1_RESOURCE = "/cert/dsa1.x509";

    @SuppressWarnings("serial")
    private static final Map<SignatureAlgorithm, String> SIG_RSA_KEY1_RESOURCE_MAP = new HashMap<SignatureAlgorithm, String>()
    {
        {
            /*
             * Created using LONG_MESSAGE
             */
            put(SignatureAlgorithm.NONE_RSA, "/sig/sig.none.rsa.data");
            put(SignatureAlgorithm.MD2_RSA, "/sig/sig.md2.rsa.data");
            put(SignatureAlgorithm.MD5_RSA, "/sig/sig.md5.rsa.data");
            put(SignatureAlgorithm.SHA1_RSA, "/sig/sig.sha1.rsa.data");
            put(SignatureAlgorithm.SHA256_RSA, "/sig/sig.sha256.rsa.data");
            put(SignatureAlgorithm.SHA384_RSA, "/sig/sig.sha384.rsa.data");
            put(SignatureAlgorithm.SHA512_RSA, "/sig/sig.sha512.rsa.data");
        }
    };

    private static final String LONG_MESSAGE = "qwertyuioplkjhgfdsazxcvbnm0987654321";
    private static final String SHORT_MESSAGE = "1234567890mnbvcxzasd";

    @Test
    public void testRsaSignDeterministic() throws IOException,
                                          InvalidKeyException,
                                          InvalidKeySpecException,
                                          SignatureException
    {
        for (SignatureAlgorithm sigAlg : SignatureAlgorithm.getRsaAlgorithms())
        {
            InputStream key = getRsaKey1();

            try
            {
                byte[] actual = X509Utils.sign(LONG_MESSAGE,
                                               key,
                                               KeyAlgorithm.RSA,
                                               sigAlg);

                InputStream expectedSteam = getSigRsaKey1Expected(sigAlg);
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
    public void testVerifyRsaCorrect() throws IOException,
                                      CertificateException,
                                      InvalidKeyException,
                                      SignatureException,
                                      InvalidKeySpecException
    {
        for (SignatureAlgorithm sigAlg : SignatureAlgorithm.getRsaAlgorithms())
        {
            InputStream key = getRsaKey1();
            InputStream cert = getRsaCert1();

            try
            {
                try
                {
                    Assert.assertTrue(sigAlg + " mismatch",
                                      X509Utils.verify(LONG_MESSAGE,
                                                       X509Utils.sign(LONG_MESSAGE,
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
    public void testVerifyDsaCorrect() throws IOException,
                                      CertificateException,
                                      InvalidKeyException,
                                      SignatureException,
                                      InvalidKeySpecException
    {
        for (SignatureAlgorithm sigAlg : SignatureAlgorithm.getDsaAlgorithms())
        {
            InputStream key = getDsaKey1();
            InputStream cert = getDsaCert1();

            try
            {
                try
                {
                    Assert.assertTrue(sigAlg + " mismatch",
                                      X509Utils.verify(SHORT_MESSAGE,
                                                       X509Utils.sign(SHORT_MESSAGE,
                                                                      key,
                                                                      KeyAlgorithm.DSA,
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
        InputStream key = getRsaKey1();
        InputStream cert = getRsaCert1();

        SignatureAlgorithm sigAlg = SignatureAlgorithm.MD5_RSA;

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(SHORT_MESSAGE,
                                                    X509Utils.sign(LONG_MESSAGE,
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

    @Test
    public void testVerifyKeyIncorrect() throws IOException,
                                        CertificateException,
                                        InvalidKeyException,
                                        SignatureException,
                                        InvalidKeySpecException
    {
        InputStream key = getRsaKey1();
        InputStream cert = getRsaCert2();

        String message = LONG_MESSAGE;
        SignatureAlgorithm sigAlg = SignatureAlgorithm.MD5_RSA;

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(message,
                                                    X509Utils.sign(message,
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

    @Test
    public void testVerifySignatureAlgorithmIncorrect() throws IOException,
                                                       CertificateException,
                                                       InvalidKeyException,
                                                       SignatureException,
                                                       InvalidKeySpecException
    {
        InputStream key = getRsaKey1();
        InputStream cert = getRsaCert2();

        String message = LONG_MESSAGE;

        try
        {
            try
            {
                Assert.assertFalse(X509Utils.verify(message,
                                                    X509Utils.sign(message,
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

    private InputStream getRsaKey1() throws IOException
    {
        return getResource(RSA_KEY1_RESOURCE);
    }

    private InputStream getRsaCert1() throws IOException
    {
        return getResource(RSA_CERT1_RESOURCE);
    }

    private InputStream getRsaCert2() throws IOException
    {
        return getResource(RSA_CERT2_RESOURCE);
    }

    private InputStream getDsaKey1() throws IOException
    {
        return getResource(DSA_KEY1_RESOURCE);
    }

    private InputStream getDsaCert1() throws IOException
    {
        return getResource(DSA_CERT1_RESOURCE);
    }

    private InputStream getSigRsaKey1Expected(SignatureAlgorithm sigAlg) throws IOException
    {
        return getResource(SIG_RSA_KEY1_RESOURCE_MAP.get(sigAlg));
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
