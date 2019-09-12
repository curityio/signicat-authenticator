package io.curity.identityserver.plugin.signicat.authentication

import com.signicat.services.client.ScSecurityException
import com.signicat.services.client.ScSystemException
import com.signicat.services.client.saml.SamlConfigConstants
import com.signicat.services.client.saml.SamlFacade
import com.signicat.services.client.saml.SamlResponseData
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.matchers.types.shouldBeSameInstanceAs
import io.kotlintest.shouldThrow
import io.kotlintest.specs.BehaviorSpec
import io.mockk.every
import io.mockk.mockk
import se.curity.identityserver.sdk.service.crypto.SignerTrustCryptoStore
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Properties

const val keystorePass = "signicat-pass"
const val preProdSignicatPemResource = "/preprod.signicat.com-2019.pem"
const val externalSignicatPemResource = "/signicat-external-ca.pem"
const val signicatAuthenticatorUrl = "https://localhost:8443/dev/authn/authenticate/signicat1/callback"

fun parseCertificateFromPem(inputStream: InputStream): X509Certificate {
    return CertificateFactory.getInstance("X.509").generateCertificate(inputStream) as X509Certificate
}

fun wrapIntoKeystore(cert: X509Certificate, pass: String = keystorePass, type: String = "jks"): KeyStore {
    val keystore = KeyStore.getInstance(type)
    keystore.load(null, pass.toCharArray())
    keystore.setCertificateEntry("default", cert)
    return keystore
}

fun KeyStore.toBytes(pass: String = keystorePass): ByteArray {
    val stream = ByteArrayOutputStream()
    store(stream, pass.toCharArray())
    return stream.toByteArray()
}

fun readSamlResponse(responseXmlResource: String, pemResource: String): SamlResponseData {
    val base64SamlResponse = Base64.getEncoder().encodeToString(
            SamlResponseCanBeParsedTest::class.java.getResource(responseXmlResource)!!.readBytes())

    val certificate = SamlResponseCanBeParsedTest::class.java.getResource(pemResource)!!.openStream().use {
        parseCertificateFromPem(it)
    }

    val jks = wrapIntoKeystore(certificate)

    val samlFacade = SamlFacade(Properties().apply {
        setProperty("debug", "true")
        setProperty(SamlConfigConstants.CONFIG_PARAMETER_TRUSTKEYSTORE_PASSWORD, keystorePass)
        setProperty("asserting.party.certificate.subject.dn",
                "CN=test.signicat.com/std, OU=Signicat, O=Signicat, L=Trondheim, ST=Norway, C=NO")
    })

    samlFacade.setSamlKeystore(jks.toBytes())

    return samlFacade.readSamlResponse(base64SamlResponse, URL(signicatAuthenticatorUrl))
}

class CanConvertCertificateKeystoreToJksTest : BehaviorSpec({
    given("A X509 Certificate imported into a Keystore that is not JKS") {
        val certificate = SamlResponseCanBeParsedTest::class.java
                .getResource(preProdSignicatPemResource)!!.openStream().use {
            parseCertificateFromPem(it)
        }

        val pkcsKeystore = wrapIntoKeystore(certificate, "pass", "PKCS12")

        val cryptoStore = mockk<SignerTrustCryptoStore>() {
            every { getCertificate() } returns certificate
            every { keyStorePassword } returns "pass".toCharArray()
            every { asKeyStore } returns pkcsKeystore
            every { keyStoreAlias } returns "default"
        }

        `when`("The Keystore is converted into JKS") {
            val jks = cryptoStore.convertToJks()

            then("the JKS should contain the same certificate") {
                jks.getCertificate("default") == certificate
            }
        }
    }
})

class JksKeystoreDoesNotRequireConvertionTest : BehaviorSpec({
    given("A JKS Keystore with a certificate in it") {
        val certificate = SamlResponseCanBeParsedTest::class.java
                .getResource(preProdSignicatPemResource)!!.openStream().use {
            parseCertificateFromPem(it)
        }

        val jksStore = wrapIntoKeystore(certificate, "pass", "jks")

        val cryptoStore = mockk<SignerTrustCryptoStore>() {
            every { asKeyStore } returns jksStore
        }

        `when`("The Keystore is converted into JKS") {
            val jks = cryptoStore.convertToJks()

            then("the JKS should be just returned as it is") {
                jks shouldBeSameInstanceAs jksStore
            }
        }
    }
})

class SamlResponseCanBeParsedTest : BehaviorSpec({
    given("A SAML response signed with Signicat's certificate") {
        `when`("A sample, valid but expired response is read") {
            val readResponse = {
                readSamlResponse("/sample-response.xml", externalSignicatPemResource)
            }

            then("An error occurs due to expiration of the response, not signature or certificate") {
                val error = shouldThrow<ScSecurityException>(readResponse)
                error.message.shouldContain("The assertion is expired.")
            }
        }
    }
})

class TamperedWithSamlResponseIsNotAccepted_Algorithm_Test : BehaviorSpec({
    given("A tampered with SAML response signed with Signicat's certificate") {
        `when`("A tampered with (Algorithm) response is read") {
            val readResponse = {
                readSamlResponse("/tampered-Algorithm-response.xml", externalSignicatPemResource)
            }

            then("An error occurs due to the message signature not matching") {
                val error = shouldThrow<ScSecurityException>(readResponse)
                error.message.shouldContain("Failed while verifying SAML response signature")
            }
        }
    }
})

class TamperedWithSamlResponseIsNotAccepted_AuthenticationMethod_Test : BehaviorSpec({
    given("A tampered with SAML response signed with Signicat's certificate") {
        `when`("A tampered with (AuthenticationMethod) response is read") {
            val readResponse = {
                readSamlResponse("/tampered-AuthenticationMethod-response.xml", externalSignicatPemResource)
            }

            then("An error occurs due to the message signature not matching") {
                val error = shouldThrow<ScSecurityException>(readResponse)
                error.message.shouldContain("Failed while verifying SAML response signature")
            }
        }
    }
})

class TamperedWithSamlResponseIsNotAccepted_NoSignature_Test : BehaviorSpec({
    given("A tampered with SAML response") {
        `when`("A tampered with (NoSignature) response is read") {
            val readResponse = {
                readSamlResponse("/tampered-NoSignature-response.xml", externalSignicatPemResource)
            }

            then("An error occurs due to the message signature not matching") {
                val error = shouldThrow<ScSystemException>(readResponse)
                error.message.shouldContain("Failed while decoding SAML response")
            }
        }
    }
})

class TamperedWithSamlResponseIsNotAccepted_NotOnOrAfter_Test : BehaviorSpec({
    given("A tampered with SAML response signed with Signicat's certificate") {
        `when`("A tampered with (NotOnOrAfter) response is read") {
            val readResponse = {
                readSamlResponse("/tampered-NotOnOrAfter-response.xml", externalSignicatPemResource)
            }

            then("An error occurs due to the message signature not matching") {
                val error = shouldThrow<ScSecurityException>(readResponse)
                error.message.shouldContain("Failed while verifying SAML response signature")
            }
        }
    }
})
