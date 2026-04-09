/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
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
 * HSM-aware PSS signing utility for PKCS#11 / SunPKCS11 provider.
 *
 * <h3>Problem</h3>
 * Nimbus JOSE+JWT uses BouncyCastle's algorithm name {@code SHA256withRSAandMGF1} for PS256.
 * BouncyCastle is the <b>only</b> JCA provider that registers this name, and BC rejects HSM
 * keys because {@code P11PrivateKey} does not implement {@code java.security.interfaces.RSAPrivateKey}.
 * <p>
 * With RS256 ({@code SHA256withRSA}), 4 providers share the name (SunRsaSign, SunJSSE, BC,
 * SunPKCS11), so JCA auto-reroutes to SunPKCS11 when the first 3 fail. With PS256
 * ({@code SHA256withRSAandMGF1}), BC has a monopoly — no fallback exists.
 *
 * <h3>Solution</h3>
 * This utility bypasses Nimbus's signing pipeline entirely for PS256/PS384/PS512 when HSM
 * is enabled. It performs raw JCA signing using the SunPKCS11 provider with the standard
 * JCA algorithm name {@code SHA256withRSASSA-PSS} (instead of BC's {@code SHA256withRSAandMGF1}).
 *
 * <h3>Algorithm name mapping</h3>
 * <pre>
 * | JWS Algorithm | Nimbus/BC Name (BROKEN with HSM)  | SunPKCS11 Name (WORKS) |
 * |---------------|-----------------------------------|------------------------|
 * | PS256         | SHA256withRSAandMGF1              | SHA256withRSASSA-PSS   |
 * | PS384         | SHA384withRSAandMGF1              | SHA384withRSASSA-PSS   |
 * | PS512         | SHA512withRSAandMGF1              | SHA512withRSASSA-PSS   |
 * </pre>
 *
 * <h3>Usage</h3>
 * <pre>
 * // Guard — place before any Nimbus RSASSASigner call:
 * if (HsmSigningHelper.isHSMEnabled() &amp;&amp; HsmSigningHelper.isPSSAlgorithm(algorithm)) {
 *     byte[] signatureBytes = HsmSigningHelper.signPSS(signingInput, privateKey, algorithm);
 *     // manually construct JWS compact serialization
 * } else {
 *     // normal Nimbus path
 *     JWSSigner signer = new RSASSASigner(privateKey);
 * }
 * </pre>
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html">
 *      PKCS#11 Reference Guide</a>
 */
public class HsmSigningHelper {

    private static final Log log = LogFactory.getLog(HsmSigningHelper.class);

    private static final String HSM_CONFIG_KEY = "Security.HSMKeyStore.Enabled";

    private HsmSigningHelper() {

        // Utility class — prevent instantiation.
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /**
     * Check if HSM is enabled in Carbon server configuration.
     * Reads {@code Security.HSMKeyStore.Enabled} from {@code deployment.toml}.
     *
     * @return {@code true} if HSM keystore is enabled.
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
     * @return {@code true} if the algorithm is PS256, PS384, or PS512.
     */
    public static boolean isPSSAlgorithm(JWSAlgorithm algorithm) {

        return JWSAlgorithm.PS256.equals(algorithm)
                || JWSAlgorithm.PS384.equals(algorithm)
                || JWSAlgorithm.PS512.equals(algorithm);
    }

    /**
     * Sign data using JCA Signature API with the SunPKCS11 provider.
     * This bypasses Nimbus JOSE+JWT / BouncyCastle entirely.
     *
     * <p>The caller is responsible for constructing the signing input (e.g.,
     * {@code header.payload} for JWS) and assembling the final output
     * (e.g., JWS compact serialization or detached JWS).</p>
     *
     * @param signingInput The data to sign (typically {@code header.payload} bytes).
     * @param privateKey   The HSM-backed P11PrivateKey.
     * @param algorithm    JWS algorithm (PS256, PS384, or PS512).
     * @return Raw signature bytes (caller must Base64URL-encode as needed).
     * @throws GeneralSecurityException If signing fails (no provider, invalid key, etc.).
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

    // ========================================================================
    // Provider discovery
    // ========================================================================

    /**
     * Find the configured SunPKCS11 provider that can handle PSS signing.
     *
     * <p>Two-pass lookup:</p>
     * <ol>
     *   <li>Prefer a SunPKCS11 provider that advertises {@code SHA256withRSASSA-PSS}
     *       support (filters out the unconfigured JDK template provider).</li>
     *   <li>Fall back to the first SunPKCS11 provider if none advertise PSS.</li>
     * </ol>
     *
     * <p>Returns {@code null} if the key is not an HSM key (not a P11Key).</p>
     *
     * @param privateKey The private key to inspect.
     * @return The SunPKCS11 provider, or {@code null} if not found / not an HSM key.
     */
    public static Provider getHSMProvider(PrivateKey privateKey) {

        String keyClassName = privateKey.getClass().getName();
        if (!keyClassName.contains("P11Key") && !keyClassName.contains("pkcs11")) {
            // Not an HSM key — no provider needed.
            return null;
        }

        // Pass 1: find a SunPKCS11 provider with explicit PSS support.
        for (Provider provider : Security.getProviders()) {
            if (provider.getName().startsWith("SunPKCS11")
                    && provider.getService("Signature", "SHA256withRSASSA-PSS") != null) {
                return provider;
            }
        }

        // Pass 2: fall back to first SunPKCS11 provider.
        for (Provider provider : Security.getProviders()) {
            if (provider.getName().startsWith("SunPKCS11")) {
                return provider;
            }
        }

        return null;
    }

    // ========================================================================
    // Algorithm mapping
    // ========================================================================

    /**
     * Map a JWS algorithm to the JCA PSS algorithm name used by SunPKCS11.
     *
     * @param algorithm JWS algorithm (PS256, PS384, or PS512).
     * @return JCA algorithm name (e.g., {@code SHA256withRSASSA-PSS}).
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
     * Create PSSParameterSpec for the given JWS algorithm.
     * Parameters follow RFC 7518 §3.5 (JSON Web Algorithms — RSASSA-PSS):
     * <ul>
     *   <li>PS256: SHA-256 hash, MGF1-SHA-256, salt length 32</li>
     *   <li>PS384: SHA-384 hash, MGF1-SHA-384, salt length 48</li>
     *   <li>PS512: SHA-512 hash, MGF1-SHA-512, salt length 64</li>
     * </ul>
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
