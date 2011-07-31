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

import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A set of allowed X.509 signature algorithms.
 *
 * @author Gregory P. Moyer
 */
public enum SignatureAlgorithm
{
    /**
     * RSA with no digest
     */
    NONE_RSA("NONEwithRSA"),

    /**
     * MD2 with RSA
     */
    MD2_RSA("MD2withRSA"),

    /**
     * MD5 with RSA
     */
    MD5_RSA("MD5withRSA"),

    /**
     * SHA-1 with RSA
     */
    SHA1_RSA("SHA1withRSA"),

    /**
     * SHA-256 with RSA
     */
    SHA256_RSA("SHA256withRSA"),

    /**
     * SHA-384 with RSA
     */
    SHA384_RSA("SHA384withRSA"),

    /**
     * SHA-512 with RSA
     */
    SHA512_RSA("SHA512withRSA"),

    /**
     * DSA with no digest
     */
    NONE_DSA("NONEwithDSA"),

    /**
     * SHA-1 with DSA
     */
    SHA1_DSA("SHA1withDSA");

    @SuppressWarnings("serial")
    private static List<SignatureAlgorithm> RSA = new ArrayList<SignatureAlgorithm>()
    {
        {
            add(NONE_RSA);
            add(MD2_RSA);
            add(MD5_RSA);
            add(SHA1_RSA);
            add(SHA256_RSA);
            add(SHA384_RSA);
            add(SHA512_RSA);
        }
    };

    @SuppressWarnings("serial")
    private static List<SignatureAlgorithm> DSA = new ArrayList<SignatureAlgorithm>()
    {
        {
            add(NONE_DSA);
            add(SHA1_DSA);
        }
    };

    /**
     * Retrieve a list of algorithms that use RSA.
     *
     * @return the complete list of RSA-based algorithms
     */
    public static List<SignatureAlgorithm> getRsaAlgorithms()
    {
        return Collections.unmodifiableList(RSA);
    }

    /**
     * Retrieve a list of algorithms that use DSA.
     *
     * @return the complete list of DSA-based algorithms
     */
    public static List<SignatureAlgorithm> getDsaAlgorithms()
    {
        return Collections.unmodifiableList(DSA);
    }

    /**
     * Retrieve a list of signature algorithms that use the given key algorithm.
     *
     * @param keyAlg
     *            the key algorithm
     * @return the complete list of appropriate signature algorithms
     */
    public static List<SignatureAlgorithm> getAlgorithms(KeyAlgorithm keyAlg)
    {
        switch (keyAlg)
        {
            case RSA:
                return getRsaAlgorithms();

            case DSA:
                return getDsaAlgorithms();

            default:
                throw new IllegalArgumentException("Unknown key algorithm: "
                                                   + keyAlg);
        }
    }

    private final String algorithm;

    private SignatureAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * Get the string representation of this algorithm suitable for use with a
     * {@link Signature} in JCS.
     *
     * @return the JCS algorithm name
     */
    public String getAlgorithm()
    {
        return algorithm;
    }
}
