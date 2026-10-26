package org.keycloak.broker.bankid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.keycloak.vault.DefaultVaultRawSecret;
import org.keycloak.vault.DefaultVaultTranscriber;
import org.keycloak.vault.VaultProvider;
import org.keycloak.vault.VaultRawSecret;
import org.keycloak.vault.VaultTranscriber;

class BankidIdentityProviderConfigTest {

	private static final String PROD_URL = "https://appapi2.bankid.com";
	private static final String TEST_URL = "https://appapi2.test.bankid.com";

	// The public BankID test RP certificate; its password is published by BankID.
	private static String testKeystoreBase64() throws IOException {
		try (InputStream p12 = BankidIdentityProviderConfigTest.class.getResourceAsStream("/FPTestcert5_20240610.p12")) {
			return Base64.getMimeEncoder().encodeToString(p12.readAllBytes()) + "\n";
		}
	}

	private static VaultTranscriber vault(Map<String, String> entries) {
		return new DefaultVaultTranscriber(new VaultProvider() {
			@Override
			public VaultRawSecret obtainSecret(String key) {
				return DefaultVaultRawSecret.forBuffer(Optional.ofNullable(entries.get(key))
						.map(value -> ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8))));
			}

			@Override
			public void close() {
			}
		});
	}

	// Configured the way Terraform does it: every secret is a vault reference.
	private static BankidIdentityProviderConfig config(String apiUrl, String keystoreBase64) {
		return config(apiUrl, keystoreBase64, "qwerty123", "qwerty123");
	}

	private static BankidIdentityProviderConfig config(String apiUrl, String keystoreBase64, String keystorePassword,
			String privateKeyPassword) {
		BankidIdentityProviderConfig config = new BankidIdentityProviderConfig();
		config.setAlias("bankid");
		config.setApiUrl(apiUrl);
		config.getConfig().put(BankidIdentityProviderConfig.BANKID_KEYSTORE_BASE64_PROPERTY_NAME, "${vault.bankid-client-cert}");
		config.getConfig().put(BankidIdentityProviderConfig.BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME, "${vault.bankid-client-cert-passphrase}");
		config.getConfig().put(BankidIdentityProviderConfig.BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME, "${vault.bankid-private-key-passphrase}");
		Map<String, String> entries = new HashMap<>();
		entries.put("bankid-client-cert-passphrase", keystorePassword);
		entries.put("bankid-private-key-passphrase", privateKeyPassword);
		if (keystoreBase64 != null) {
			entries.put("bankid-client-cert", keystoreBase64);
		}
		config.resolveSecrets(vault(entries));
		return config;
	}

	@Test
	void loadsTheKeystoreFromWrappedBase64() throws Exception {
		KeyStore keyStore = config(TEST_URL, testKeystoreBase64()).getKeyStore();

		assertTrue(Collections.list(keyStore.aliases()).stream().anyMatch(alias -> {
			try {
				return keyStore.isKeyEntry(alias);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}));
	}

	@Test
	void failsWhenTheVaultEntryIsMissing() {
		assertThrows(IllegalStateException.class, () -> config(TEST_URL, null));
	}

	@Test
	void failsWithoutAKeystore() {
		BankidIdentityProviderConfig config = new BankidIdentityProviderConfig();
		config.setApiUrl(TEST_URL);
		config.resolveSecrets(vault(Map.of()));

		assertThrows(IllegalStateException.class, config::getKeyStore);
	}

	@Test
	void resolvesTheSecretsFromTheVault() throws Exception {
		BankidIdentityProviderConfig config = config(TEST_URL, testKeystoreBase64());

		assertEquals(testKeystoreBase64(), config.getKeyStoreBase64());
		assertEquals("qwerty123", config.getPrivateKeyPassword());
		// The IdP config itself keeps only the reference.
		assertEquals("${vault.bankid-client-cert}",
				config.getConfig().get(BankidIdentityProviderConfig.BANKID_KEYSTORE_BASE64_PROPERTY_NAME));
	}

	@Test
	void truststoreHoldsTheRootForTheApiHost() throws Exception {
		assertEquals("CN=BankID SSL Root CA v1,OU=Infrastructure CA,O=Finansiell ID-Teknik BID AB",
				rootSubject(config(PROD_URL, "unused").getTrustStore(), "appapi2.bankid.com"));
		assertEquals("CN=Test BankID SSL Root CA v1 Test,OU=Infrastructure CA,O=Finansiell ID-Teknik BID AB",
				rootSubject(config(TEST_URL, "unused").getTrustStore(), "appapi2.test.bankid.com"));
	}

	@Test
	void failsForAnUnknownApiHost() {
		assertThrows(IllegalStateException.class,
				() -> config("https://bankid.example.com", "unused").getTrustStore());
	}

	@Test
	void clientKeyChangesWithTheKeystoreAndPasswords() throws Exception {
		String key = BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64()));

		assertEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64())));
		assertNotEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, "cm90YXRlZA==")));
		assertNotEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64(), "changed", "qwerty123")));
		assertNotEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64(), "qwerty123", "changed")));
		assertFalse(key.contains("qwerty123"));
	}

	private static String rootSubject(KeyStore trustStore, String alias) throws Exception {
		assertEquals(1, trustStore.size());
		return ((X509Certificate) trustStore.getCertificate(alias)).getSubjectX500Principal().getName();
	}
}
