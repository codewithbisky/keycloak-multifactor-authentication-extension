package com.codewithbisky.authentication.extension.webauthn.domain;


import com.codewithbisky.authentication.extension.webauthn.model.UserAccount;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.jboss.logging.Logger;
import com.codewithbisky.authentication.extension.exception.MissingConfigException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class RelyingPartyConfiguration {


    /**
     * RelyingParty is the key object in the Yubico library you must configure it once with the settings
     * that identify the server, for example the domain name of the server.  Yubico library makes no
     * assumptions about what type of database is used to store user information, so it defines an
     * interface com.yubico.webauthn.CredentialRepository that is implemented in this package.
     * <p>
     * see Yuibco docs https://developers.yubico.com/WebAuthn/
     *
     * @param credentialRepository an implementation to save webauthn details to from the databsae
     * @return
     */
    private static final Logger logger = Logger.getLogger(RelyingPartyConfiguration.class);

    public static RelyingParty relyingParty(UserService userService, UserAccount userAccount) {
        return relyingParty(userService, userAccount, null);
    }

    public static RelyingParty relyingParty(UserService userService, UserAccount userAccount, String clientOrigin) {


        String domain = System.getenv("KC_WEBAUTHN_DOMAIN");
        String webauthnName = System.getenv("KC_WEBAUTHN_NAME");
        String iosBundleId = System.getenv("KC_WEBAUTHN_IOS_BUNDLE_ID");
        String allowedOriginsEnv = System.getenv("KC_WEBAUTHN_ALLOWED_ORIGINS");

        if (domain == null) {
            throw new MissingConfigException("KC_WEBAUTHN_DOMAIN environment variable not set");
        }

        CredentialRepositoryImpl credentialRepositoryImpl = new CredentialRepositoryImpl(userService,
                userAccount == null ? Optional.empty() : Optional.of(userAccount));
        RelyingPartyIdentity rpIdentity =
                RelyingPartyIdentity.builder()
                        .id(domain) // Set this to a parent domain that covers all subdomains// where
                        .name(webauthnName == null ? "CodeWithBisky" : webauthnName)
                        .build();

        // Build allowed origins set including web, Android, and iOS origins
        Set<String> allowedOrigins = new HashSet<>();

        // Add primary domain origin
        allowedOrigins.add("https://" + domain);

        // Add additional allowed origins from environment variable (comma-separated)
        if (allowedOriginsEnv != null && !allowedOriginsEnv.trim().isEmpty()) {
            String[] origins = allowedOriginsEnv.split(",");
            for (String origin : origins) {
                String trimmedOrigin = origin.trim();
                if (!trimmedOrigin.isEmpty()) {
                    allowedOrigins.add(trimmedOrigin);
                    logger.info("Added allowed origin: " + trimmedOrigin);
                }
            }
        } else {
            // Default localhost origins for development if not configured
            allowedOrigins.add("http://localhost");
            allowedOrigins.add("http://localhost:3000");
            allowedOrigins.add("http://localhost:3443");
            allowedOrigins.add("https://localhost:3443");
            logger.info("Using default localhost origins (no KC_WEBAUTHN_ALLOWED_ORIGINS configured)");
        }

        // Add iOS origins if configured
        if (iosBundleId != null) {
            allowedOrigins.add("ios:bundle-id:" + iosBundleId);
        }

        // Add client origin if provided (for mobile platforms)
        if (clientOrigin != null && !clientOrigin.isEmpty()) {
            allowedOrigins.add(clientOrigin);
        }

        /**
         * IMPORTANT: Mobile Platform Support (Android & iOS)
         *
         * The Yubico WebAuthn library validates origins strictly for web applications.
         * However, mobile platforms use different origin formats:
         * - Android: android:apk-key-hash:<base64url-sha1-hash>
         * - iOS: ios:bundle-id:<bundle-id>
         *
         * The Yubico library (version 2.5.2) does not support custom origin validators,
         * so we cannot validate these mobile origins directly.
         *
         * SECURITY MODEL FOR MOBILE:
         * - Android: Security is ensured by Digital Asset Links verification
         *   The Android OS verifies the app's signature against assetlinks.json
         *   before allowing WebAuthn operations.
         *
         * - iOS: Security is ensured by Associated Domains verification
         *   The iOS OS verifies the app's bundle ID against apple-app-site-association
         *   before allowing WebAuthn operations.
         *
         * WORKAROUND:
         * We disable origin validation entirely when mobile platforms are configured.
         * This is safe because the platform-level verification provides the security.
         */

        RelyingParty.RelyingPartyBuilder builder = RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepositoryImpl)
                .allowOriginPort(true)
                .allowOriginSubdomain(true)
                .validateSignatureCounter(false); // Disable signature counter for mobile compatibility



        // Always set origins - this includes web origins and dynamically added mobile origins
        builder.origins(allowedOrigins);

        return builder.build();
    }
}
