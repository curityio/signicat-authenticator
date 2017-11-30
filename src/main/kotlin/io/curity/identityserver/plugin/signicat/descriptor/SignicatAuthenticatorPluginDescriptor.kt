package io.curity.identityserver.plugin.signicat.descriptor

import io.curity.identityserver.plugin.signicat.authentication.SignicatAuthenticatorRequestHandler
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor

class SignicatAuthenticatorPluginDescriptor : AuthenticatorPluginDescriptor<SignicatAuthenticatorPluginConfig>
{
    override fun getAuthenticationRequestHandlerTypes(): Map<String, Class<out AuthenticatorRequestHandler<*>>> =
            mapOf("index" to SignicatAuthenticatorRequestHandler::class.java)
    
    override fun getConfigurationType(): Class<out SignicatAuthenticatorPluginConfig> = SignicatAuthenticatorPluginConfig::class.java
    
    override fun getPluginImplementationType(): String = "signicat-authenticator"
}