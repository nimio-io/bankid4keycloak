package org.keycloak.broker.bankid;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Map;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

public class BankidIdentityProviderConfig extends IdentityProviderModel {
	/**
	 * 
	 */
	private static final long serialVersionUID = 3849007589404817838L;

	public static final String BANKID_APIURL_PROPERTY_NAME = "bankid_apiurl";
	public static final String BANKID_KEYSTORE_BASE64_PROPERTY_NAME = "bankid_keystore_base64";
	public static final String BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME = "bankid_keystore_password";
	public static final String BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME = "bankid_privatekey_password";
	public static final String BANKID_REQUIRE_NIN = "bankid_require_nin";
	public static final String BANKID_SHOW_QR_CODE = "bankid_show_qr_code";
	public static final String BANKID_SAVE_NIN_HASH = "bankid_save_nin_hash";
	public static final String BANKID_CONNECTION_POOL_SIZE = "bankid_connection_pool_size";
	public static final String BANKID_MAX_POOLED_PER_ROUTE = "bankid_max_pooled_per_route";

	// The BankID server certificates are issued by these roots, one per
	// environment. They are public, so they ship in the jar and are picked by the
	// API host instead of being configured.
	private static final Map<String, String> ROOT_CA_BY_HOST = Map.of(
			"appapi2.bankid.com", "bankid-ca/BankID_SSL_Root_CA_v1.pem",
			"appapi2.test.bankid.com", "bankid-ca/Test_BankID_SSL_Root_CA_v1_Test.pem");

	// Resolved by resolveSecrets: the config holds ${vault.<key>} references so
	// the keystore and its passwords never sit in the IdP representation.
	private String keyStoreBase64;
	private String keyStorePassword;
	private String privateKeyPassword;

	private KeyStore keyStore;
	private KeyStore truststore;

	public BankidIdentityProviderConfig() {
		super();
	}

	public BankidIdentityProviderConfig(IdentityProviderModel model) {
		super(model);
	}

	public String getApiUrl() {
		return getConfig().get(BANKID_APIURL_PROPERTY_NAME);
	}

	public void setApiUrl(final String apiUrl) {
		getConfig().put(BANKID_APIURL_PROPERTY_NAME, apiUrl);
	}

	/**
	 * Resolves the keystore and its passwords through the Keycloak vault. A
	 * ${vault.<key>} value is read from the vault; a missing vault entry throws.
	 */
	public void resolveSecrets(VaultTranscriber vault) {
		keyStoreBase64 = resolve(vault, BANKID_KEYSTORE_BASE64_PROPERTY_NAME, null);
		keyStorePassword = resolve(vault, BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME, "changeit");
		privateKeyPassword = resolve(vault, BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME, "changeit");
	}

	private String resolve(VaultTranscriber vault, String property, String defaultValue) {
		String value = getConfig().get(property);
		if (value == null || value.isBlank()) {
			return defaultValue;
		}
		try (VaultStringSecret secret = vault.getStringSecret(value)) {
			return secret.get().orElseThrow(() -> new IllegalStateException(
					property + " references a vault entry that does not exist: " + value));
		}
	}

	public String getKeyStoreBase64() {
		return requireResolved(keyStoreBase64, BANKID_KEYSTORE_BASE64_PROPERTY_NAME);
	}

	public KeyStore getKeyStore() throws Exception {
		if (keyStore == null) {
			// The MIME decoder skips line breaks, so wrapped base64 (or a trailing
			// newline from `base64 file | gcloud secrets versions add`) still loads.
			byte[] pkcs12 = Base64.getMimeDecoder().decode(getKeyStoreBase64());
			KeyStore loaded = KeyStore.getInstance("PKCS12");
			loaded.load(new ByteArrayInputStream(pkcs12), requireResolved(keyStorePassword, BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME).toCharArray());
			keyStore = loaded;
		}
		return keyStore;
	}

	private String requireResolved(String value, String property) {
		if (value == null) {
			throw new IllegalStateException(property + " is not set (or resolveSecrets was not called)");
		}
		return value;
	}

	public KeyStore getTrustStore() throws Exception {
		if (truststore == null) {
			String host = URI.create(getApiUrl()).getHost();
			String resource = ROOT_CA_BY_HOST.get(host);
			if (resource == null) {
				throw new IllegalStateException("No BankID root CA for API host " + host
						+ "; expected one of " + ROOT_CA_BY_HOST.keySet());
			}
			KeyStore loaded = KeyStore.getInstance(KeyStore.getDefaultType());
			loaded.load(null, null);
			try (InputStream pem = BankidIdentityProviderConfig.class.getClassLoader().getResourceAsStream(resource)) {
				if (pem == null) {
					throw new IOException("Missing bundled BankID root CA " + resource);
				}
				loaded.setCertificateEntry(host, CertificateFactory.getInstance("X.509").generateCertificate(pem));
			}
			truststore = loaded;
		}
		return truststore;
	}

	public String getPrivateKeyPassword() {
		return requireResolved(privateKeyPassword, BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME);
	}

	public boolean isShowQRCode() {
		return Boolean.valueOf(getConfig().getOrDefault(BANKID_SHOW_QR_CODE, "false"));
	}

	public boolean isRequiredNin() {
		return Boolean.valueOf(getConfig().getOrDefault(BANKID_REQUIRE_NIN, "false"));
	}

	public void setRequiredNin(boolean requiredNin) {
		getConfig().put(BANKID_REQUIRE_NIN, String.valueOf(requiredNin));
	}


	public boolean isSaveNinHashed() {
		return Boolean.valueOf(getConfig().getOrDefault(BANKID_SAVE_NIN_HASH, "false"));
	}

	public int getConnectionPoolSize() {
		return parsePositiveInt(BANKID_CONNECTION_POOL_SIZE, 200);
	}

	public int getConnectionPoolPerRoute() {
		int value = parsePositiveInt(BANKID_MAX_POOLED_PER_ROUTE, 50);
		int total = getConnectionPoolSize();
		return value > total ? total : value;
	}

	private int parsePositiveInt(String key, int defaultValue) {
		String raw = getConfig().get(key);
		if (raw == null || raw.trim().isEmpty()) {
			return defaultValue;
		}

		try {
			int parsed = Integer.parseInt(raw.trim());
			return parsed > 0 ? parsed : defaultValue;
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}
}
