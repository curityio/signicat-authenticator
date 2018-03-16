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
import se.curity.identityserver.sdk.config.annotation.DefaultEnum
import se.curity.identityserver.sdk.config.annotation.DefaultOption
import se.curity.identityserver.sdk.config.annotation.DefaultString
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.UserPreferenceManager
import se.curity.identityserver.sdk.service.WebServiceClientFactory
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider
import java.util.Optional

interface SignicatAuthenticatorPluginConfig : Configuration
{
    val exceptionFactory: ExceptionFactory
    
    val userPreferencesManager : UserPreferenceManager
    
    @get:Description("A country's type of authentication which should be used (e.g., Swedish BankID or Danish NemID)")
    @get:DefaultEnum("SWEDEN")
    val country: Country
    
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
    
    @get:Description("Whether or not authentication should be obtained by signing")
    val useSigning: Optional<UseSigning>
    
    interface UseSigning
    {
        @get:Description("The client secret used to authenticate to the Signicat signing service")
        val secret : String
    }
    
    val authenticationInformationProvider : AuthenticatorInformationProvider
}

enum class PredefinedEnvironment
{
    @Description("Non-production environment for testing and verification")
    PRE_PRODUCTION,
    
    @Description("The production environment should be use")
    PRODUCTION
}

enum class Country
{
    @Description("Require that the user login with Swedish BankID")
    SWEDEN,
    
    @Description("Require that the user login with Danish NemID")
    DENMARK,
    
    @Description("Require that the user login with Finish Tupas")
    FINLAND,
    
    @Description("Require that the user login with Norwegian BankID")
    NORWAY,
    
    @Description("Require that the user login with an Estonian E-ID")
    ESTONIA
}