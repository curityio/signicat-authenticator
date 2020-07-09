/*
 *  Copyright 2018 Curity AB
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

package io.curity.identityserver.plugin.signicat.config

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.OneOf
import se.curity.identityserver.sdk.config.annotation.DefaultOption
import se.curity.identityserver.sdk.config.annotation.DefaultString
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.config.annotation.Suggestions
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.UserPreferenceManager
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider
import se.curity.identityserver.sdk.service.crypto.ClientKeyCryptoStore
import se.curity.identityserver.sdk.service.crypto.ServerTrustCryptoStore
import se.curity.identityserver.sdk.service.crypto.SignerTrustCryptoStore
import java.util.Optional

interface SignicatAuthenticatorPluginConfig : Configuration
{
    val exceptionFactory: ExceptionFactory
    
    val userPreferencesManager : UserPreferenceManager

    @get:Description("The kind of E-ID that the user should use when logging in")
    @get:Suggestions("sbid", "nemid", "nbid", "tupas", "esteid")
    @get:DefaultString("sbid")
    val method: String
    
    @get:Description("The service that has been registered with Signicat")
    @get:DefaultString("demo")
    val serviceName: String
    
    @get:Description("The environment to connect to")
    val environment: Environment
    
    interface Environment : OneOf
    {
        @get:DefaultOption
        val standardEnvironment : Optional<PredefinedEnvironment>
        
        val customEnvironment : Optional<String>
    }

    @get:Description("The name of the graphics profile that should be used at Signicat")
    val graphicsProfile: Optional<String>
    
    @get:Description("Whether or not to send a text that should be signed by authenticating")
    val useSigning: Optional<UseSigning>
    
    interface UseSigning
    {
        @get:Description("The client secret used to authenticate to the Signicat signing service")
        val secret : String

        @get:Description("The text that should be presented to the user for signing")
        @get:DefaultString("Authenticate to sign this text")
        val toBeSigned: String

        @get:Description("The title of the signing page that Signicat should show")
        @get:DefaultString("Authenticate to sign")
        val signingDescription: String

        val clientKeyCryptoStore: Optional<ClientKeyCryptoStore>
    }
    
    val sessionManager : SessionManager
    
    val authenticatorInformationProvider: AuthenticatorInformationProvider

    val serverTrustCryptoStore: Optional<ServerTrustCryptoStore>

    val signerTrustCryptoStore: Optional<SignerTrustCryptoStore>
}

enum class PredefinedEnvironment
{
    @Description("Non-production environment for testing and verification")
    PRE_PRODUCTION,
    
    @Description("The production environment should be use")
    PRODUCTION
}
