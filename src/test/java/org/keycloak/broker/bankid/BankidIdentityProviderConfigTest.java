package org.keycloak.broker.bankid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

import org.junit.jupiter.api.Test;

class BankidIdentityProviderConfigTest {

	private static final String PROD_URL = "https://appapi2.bankid.com";
	private static final String TEST_URL = "https://appapi2.test.bankid.com";

	// The public BankID test RP certificate; its password is published by BankID.
	private static String testKeystoreBase64() throws IOException {
		try (InputStream p12 = BankidIdentityProviderConfigTest.class.getResourceAsStream("/FPTestcert5_20240610.p12")) {
			return Base64.getMimeEncoder().encodeToString(p12.readAllBytes()) + "\n";
		}
	}

	private static BankidIdentityProviderConfig config(String apiUrl, String keystoreBase64) {
		BankidIdentityProviderConfig config = new BankidIdentityProviderConfig();
		config.setAlias("bankid");
		config.setApiUrl(apiUrl);
		if (keystoreBase64 != null) {
			config.getConfig().put(BankidIdentityProviderConfig.BANKID_KEYSTORE_BASE64_PROPERTY_NAME, keystoreBase64);
		}
		config.getConfig().put(BankidIdentityProviderConfig.BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME, "qwerty123");
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
	void failsWithoutAKeystore() {
		assertThrows(IllegalStateException.class, () -> config(TEST_URL, null).getKeyStore());
	}

	@Test
	void truststoreHoldsTheRootForTheApiHost() throws Exception {
		assertEquals("CN=BankID SSL Root CA v1,OU=Infrastructure CA,O=Finansiell ID-Teknik BID AB",
				rootSubject(config(PROD_URL, null).getTrustStore(), "appapi2.bankid.com"));
		assertEquals("CN=Test BankID SSL Root CA v1 Test,OU=Infrastructure CA,O=Finansiell ID-Teknik BID AB",
				rootSubject(config(TEST_URL, null).getTrustStore(), "appapi2.test.bankid.com"));
	}

	@Test
	void failsForAnUnknownApiHost() {
		assertThrows(IllegalStateException.class,
				() -> config("https://bankid.example.com", null).getTrustStore());
	}

	@Test
	void clientKeyChangesWithTheKeystore() throws Exception {
		String key = BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64()));

		assertEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, testKeystoreBase64())));
		assertNotEquals(key, BankidIdentityProviderFactory.clientKey(config(PROD_URL, "cm90YXRlZA==")));
	}

	private static String rootSubject(KeyStore trustStore, String alias) throws Exception {
		assertEquals(1, trustStore.size());
		return ((X509Certificate) trustStore.getCertificate(alias)).getSubjectX500Principal().getName();
	}
}
