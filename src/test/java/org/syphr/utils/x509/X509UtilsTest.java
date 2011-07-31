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

import junit.framework.Assert;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.syphr.utils.x509.KeyAlgorithm;
import org.syphr.utils.x509.SignatureAlgorithm;
import org.syphr.utils.x509.X509Utils;

public class X509UtilsTest
{
    private static final String KEY_RESOURCE = "/cert/test.pkcs8";
    private static final String CERT_RESOURCE = "/cert/test.cert";

    private static final String SIG_RESOURCE = "/sig/sig.data";

    private static final String MESSAGE = "qwertyuioplkjhgfdsazxcvbnm0987654321";

    @Test
    public void testSign() throws IOException,
                          InvalidKeyException,
                          InvalidKeySpecException,
                          SignatureException
    {
        InputStream key = getKey();

        try
        {
            byte[] actual = X509Utils.sign(MESSAGE,
                                           key,
                                           KeyAlgorithm.RSA,
                                           SignatureAlgorithm.MD5_RSA);

            InputStream expectedSteam = getSigExpected();
            try
            {
                byte[] expected = IOUtils.toByteArray(expectedSteam);
                Assert.assertTrue(Arrays.equals(expected, actual));
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

    @Test
    public void testVerify() throws IOException,
                            CertificateException,
                            InvalidKeyException,
                            SignatureException,
                            InvalidKeySpecException
    {
        InputStream key = getKey();
        InputStream cert = getCert();

        try
        {
            try
            {
                Assert.assertTrue(X509Utils.verify(MESSAGE,
                                                   X509Utils.sign(MESSAGE,
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

    private InputStream getKey() throws IOException
    {
        return getResource(KEY_RESOURCE);
    }

    private InputStream getCert() throws IOException
    {
        return getResource(CERT_RESOURCE);
    }

    private InputStream getSigExpected() throws IOException
    {
        return getResource(SIG_RESOURCE);
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
