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

import java.security.KeyFactory;

/**
 * A set of allowed private key algorithms for creating X.509 signatures.
 *
 * @author Gregory P. Moyer
 */
public enum KeyAlgorithm
{
    /**
     * RSA
     */
    RSA("RSA");

    private final String algorithm;

    private KeyAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * Get the string representation of this algorithm suitable for use with a
     * {@link KeyFactory} in JCS.
     *
     * @return the JCS algorithm name
     */
    public String getAlgorithm()
    {
        return algorithm;
    }
}
