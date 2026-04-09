/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Utility class for HSM-aware PSS signing using SunPKCS11 provider.
 * Bypasses Nimbus/BouncyCastle for PS256/PS384/PS512 when HSM is enabled,
 * since BC's algorithm name (SHA256withRSAandMGF1) is incompatible with SunPKCS11.
 */
public class HsmSigningHelper {

    private static final Log log = LogFactory.getLog(HsmSigningHelper.class);

    private static final String HSM_CONFIG_KEY = "Security.HSMKeyStore.Enabled";

    private HsmSigningHelper() {

    }

    /**
     * Check if HSM is enabled in Carbon server configuration.
     *
     * @return true if HSM keystore is enabled.
     */
    public static boolean isHSMEnabled() {

        String hsmEnabled = CarbonUtils.getServerConfiguration()
                .getFirstProperty(HSM_CONFIG_KEY);
        boolean enabled = Boolean.parseBoolean(hsmEnabled);
        if (log.isDebugEnabled()) {
            log.debug("HSM status check: enabled=" + enabled + " (raw value: " + hsmEnabled + ")");
        }
        return enabled;
    }

    /**
     * Check if the given JWS algorithm is a PSS variant (PS256, PS384, PS512).
     *
     * @param algorithm JWS algorithm to check.
     * @return true if the algorithm is PS256, PS384, or PS512.
     */
    public static boolean isPSSAlgorithm(JWSAlgorithm algorithm) {

        return JWSAlgorithm.PS256.equals(algorithm)
                || JWSAlgorithm.PS384.equals(algorithm)
                || JWSAlgorithm.PS512.equals(algorithm);
    }

    /**
     * Sign data using JCA Signature API with the SunPKCS11 provider.
     * Bypasses Nimbus JOSE+JWT / BouncyCastle entirely for PSS algorithms.
     *
     * @param signingInput The data to sign.
     * @param privateKey   The HSM-backed private key.
     * @param algorithm    JWS algorithm (PS256, PS384, or PS512).
     * @return Raw signature bytes.
     * @throws GeneralSecurityException If signing fails.
     */
    public static byte[] signPSS(byte[] signingInput, PrivateKey privateKey, JWSAlgorithm algorithm)
            throws GeneralSecurityException {

        Provider hsmProvider = getHSMProvider(privateKey);
        if (hsmProvider == null) {
            throw new GeneralSecurityException(
                    "No configured SunPKCS11 provider found for PSS signing. "
                            + "Ensure HSM is properly configured and SunPKCS11 provider is registered.");
        }

        String jcaAlgorithm = getJCAPSSAlgorithmName(algorithm);
        PSSParameterSpec pssSpec = getPSSParameterSpec(algorithm);

        if (log.isDebugEnabled()) {
            log.debug("HSM PSS signing: algorithm=" + jcaAlgorithm + ", provider=" + hsmProvider.getName()
                    + ", keyType=" + privateKey.getClass().getName());
        }

        Signature signature = Signature.getInstance(jcaAlgorithm, hsmProvider);
        signature.setParameter(pssSpec);
        signature.initSign(privateKey);
        signature.update(signingInput);

        byte[] signatureBytes = signature.sign();

        if (log.isDebugEnabled()) {
            log.debug("HSM PSS signing successful. Signature length: " + signatureBytes.length + " bytes.");
        }

        return signatureBytes;
    }

    /**
     * Find the configured SunPKCS11 provider for PSS signing.
     * Prefers a provider that advertises SHA256withRSASSA-PSS support,
     * falls back to the first SunPKCS11 provider.
     * Returns null if the key is not an HSM key.
     *
     * @param privateKey The private key to inspect.
     * @return The SunPKCS11 provider, or null if not found.
     */
    public static Provider getHSMProvider(PrivateKey privateKey) {

        String keyClassName = privateKey.getClass().getName();
        if (!keyClassName.contains("P11Key") && !keyClassName.contains("pkcs11")) {
            return null;
        }

        for (Provider provider : Security.getProviders()) {
            if (provider.getName().startsWith("SunPKCS11")
                    && provider.getService("Signature", "SHA256withRSASSA-PSS") != null) {
                return provider;
            }
        }

        for (Provider provider : Security.getProviders()) {
            if (provider.getName().startsWith("SunPKCS11")) {
                return provider;
            }
        }

        return null;
    }

    /**
     * Map a JWS algorithm to the JCA PSS algorithm name used by SunPKCS11.
     *
     * @param algorithm JWS algorithm (PS256, PS384, or PS512).
     * @return JCA algorithm name.
     * @throws IllegalArgumentException If the algorithm is not a PSS variant.
     */
    public static String getJCAPSSAlgorithmName(JWSAlgorithm algorithm) {

        if (JWSAlgorithm.PS256.equals(algorithm)) {
            return "SHA256withRSASSA-PSS";
        } else if (JWSAlgorithm.PS384.equals(algorithm)) {
            return "SHA384withRSASSA-PSS";
        } else if (JWSAlgorithm.PS512.equals(algorithm)) {
            return "SHA512withRSASSA-PSS";
        }
        throw new IllegalArgumentException("Not a PSS algorithm: " + algorithm);
    }

    /**
     * Create PSSParameterSpec for the given JWS algorithm per RFC 7518.
     *
     * @param algorithm JWS algorithm (PS256, PS384, or PS512).
     * @return PSS parameter specification.
     * @throws IllegalArgumentException If the algorithm is not a PSS variant.
     */
    public static PSSParameterSpec getPSSParameterSpec(JWSAlgorithm algorithm) {

        if (JWSAlgorithm.PS256.equals(algorithm)) {
            return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        } else if (JWSAlgorithm.PS384.equals(algorithm)) {
            return new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
        } else if (JWSAlgorithm.PS512.equals(algorithm)) {
            return new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
        }
        throw new IllegalArgumentException("Not a PSS algorithm: " + algorithm);
    }
}
