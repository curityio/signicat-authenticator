/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.signicat.descriptor

import io.curity.identityserver.plugin.signicat.authentication.SignicatAuthenticatorRequestHandler
import io.curity.identityserver.plugin.signicat.authentication.SignicatCallbackRequestHandler
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor

class SignicatAuthenticatorPluginDescriptor : AuthenticatorPluginDescriptor<SignicatAuthenticatorPluginConfig>
{
    override fun getAuthenticationRequestHandlerTypes(): Map<String, Class<out AuthenticatorRequestHandler<*>>> =
            mapOf("index" to SignicatAuthenticatorRequestHandler::class.java,
                    "callback" to SignicatCallbackRequestHandler::class.java)
    
    override fun getConfigurationType(): Class<out SignicatAuthenticatorPluginConfig> = SignicatAuthenticatorPluginConfig::class.java
    
    override fun getPluginImplementationType(): String = "signicat-authenticator"
}