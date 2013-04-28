/*
 * Copyright, 2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

final class SignedParametersUtil {
    private static final Base64 base64 = new Base64(true);
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final TypeReference<HashMap<String, String>> MAP_TYPE_REFERENCE =
        new TypeReference<HashMap<String, String>>() {
        };

    private SignedParametersUtil() {
        throw new UnsupportedOperationException("Can not be instantiated");
    }

    public static Map<String, String> verifyAndDecode(String input, String secret) throws GeneralSecurityException {
        Validate.notNull(secret, "secret must not be null");

        try {
            if (input == null || !input.contains(".")) {
                throw new IllegalArgumentException("Input does not look like signed parameters: " + input);
            }

            String[] parts = input.split("[.]", 2);
            String encodedSignature = parts[0];
            String encodedEnvelope = parts[1];

            String jsonEnvelope = new String(base64.decode(encodedEnvelope), UTF8);
            HashMap<String, String> parameters = objectMapper.readValue(jsonEnvelope, MAP_TYPE_REFERENCE);
            String algorithm = StringUtils.defaultIfEmpty(parameters.remove("algorithm"), "HMACSHA256");

            verify(secret, algorithm, encodedEnvelope, encodedSignature);

            return parameters;

        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(e);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static void verify(String secret, String algorithm, String encodedEnvelope, String encodedSignature) throws GeneralSecurityException {
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(UTF8), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKey);

        byte[] digest = mac.doFinal(encodedEnvelope.getBytes(UTF8));
        byte[] signature = base64.decode(encodedSignature);
        if (!Arrays.equals(digest, signature)) {
            throw new SignatureException("Signed parameters were tampered with");
        }
    }
}
