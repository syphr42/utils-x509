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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.io.IOUtils;

/**
 * This utility makes it easy to create and verify signatures using an X.509
 * key/certificate pair.
 *
 * @author Gregory P. Moyer
 */
public class X509Utils
{
    /**
     * The certificate factory to use. This will be lazily created on demand.
     */
    private static volatile CertificateFactory CERT_FACTORY;

    /**
     * Create a signature using the given token and private key.
     *
     * @param message
     *            the message to sign
     * @param key
     *            the private key to use to create the signature (this must be
     *            PKCS8 encoded)
     * @param keyAlg
     *            the algorithm used to create the private key
     * @param sigAlg
     *            the algorithm to use to create the signature
     * @return the signature
     * @throws IOException
     *             if there is an error reading the key
     * @throws InvalidKeySpecException
     *             if the key algorithm is not appropriate for the given private
     *             key
     * @throws InvalidKeyException
     *             if the given private key is not valid
     * @throws SignatureException
     *             if there is an error while generating the signature
     */
    public static byte[] sign(String message,
                              InputStream key,
                              KeyAlgorithm keyAlg,
                              SignatureAlgorithm sigAlg) throws IOException,
                                                        InvalidKeySpecException,
                                                        InvalidKeyException,
                                                        SignatureException
    {
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(key));

        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlg.getAlgorithm());
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature sig = Signature.getInstance(sigAlg.getAlgorithm());
            sig.initSign(privateKey);
            sig.update(message.getBytes());
            return sig.sign();
        }
        catch (NoSuchAlgorithmException e)
        {
            /*
             * This is protected against by enforcing specific algorithm
             * choices.
             */
            throw new IllegalArgumentException("Unknown algorithm", e);
        }
    }

    /**
     * Verify a signature using the given token and certificate.
     *
     * @param message
     *            the message to which the signature belongs
     * @param signature
     *            the signature to verify
     * @param sigAlg
     *            the algorithm used to create the signature
     * @param certificate
     *            the certificate to use to verify the signature
     * @return <code>true</code> if the signature is valid; <code>false</code>
     *         otherwise
     * @throws CertificateException
     *             if there is an error reading the certificate
     * @throws InvalidKeyException
     *             if the given certificate does not have a valid public key
     * @throws SignatureException
     *             if the signature is not valid
     */
    public static boolean verify(String message,
                                 byte[] signature,
                                 SignatureAlgorithm sigAlg,
                                 InputStream certificate) throws CertificateException,
                                                         InvalidKeyException,
                                                         SignatureException
    {
        Certificate cert = getCertFactory().generateCertificate(certificate);

        try
        {
            Signature sig = Signature.getInstance(sigAlg.getAlgorithm());
            sig.initVerify(cert);
            sig.update(message.getBytes());
            return sig.verify(signature);
        }
        catch (NoSuchAlgorithmException e)
        {
            /*
             * This is protected against by enforcing specific algorithm
             * choices.
             */
            throw new IllegalArgumentException("Unknown algorithm", e);
        }
    }

    /**
     * Retrieve (and possible create) the certificate factory to use when
     * reading certificates.
     *
     * @return the certificate factory
     * @throws CertificateException
     *             if no X.509 certificate provider is found
     */
    private static CertificateFactory getCertFactory() throws CertificateException
    {
        if (CERT_FACTORY == null)
        {
            synchronized (X509Utils.class)
            {
                if (CERT_FACTORY == null)
                {
                    CERT_FACTORY = CertificateFactory.getInstance("X.509");
                }
            }
        }

        return CERT_FACTORY;
    }

    private X509Utils()
    {
        /*
         * Static utilities
         */
    }
}
