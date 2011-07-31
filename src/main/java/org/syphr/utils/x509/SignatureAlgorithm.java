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

/**
 * A set of allowed X.509 signature algorithms.
 *
 * @author Gregory P. Moyer
 */
public enum SignatureAlgorithm
{
    /**
     * MD5 with RSA
     */
    MD5_RSA("MD5withRSA");

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
