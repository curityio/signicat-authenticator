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

package io.curity.identityserver.plugin.signicat.authentication

import io.curity.identityserver.plugin.signicat.config.Country
import io.curity.identityserver.plugin.signicat.config.Environment
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import io.curity.identityserver.plugin.signicat.descriptor.SignicatAuthenticatorPluginDescriptor
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.http.RedirectStatusCode
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.net.URL
import java.util.IllformedLocaleException
import java.util.Locale
import java.util.Optional

class RequestModel(request: Request)

class SignicatAuthenticatorRequestHandler(config : SignicatAuthenticatorPluginConfig)
    : AuthenticatorRequestHandler<RequestModel>
{
    private val logger: Logger = LoggerFactory.getLogger(SignicatAuthenticatorRequestHandler::class.java)
    private val exceptionFactory = config.exceptionFactory
    private val environment = config.environment
    private val service = config.serviceName
    private val profile = config.graphicsProfile
    private val country = config.country
    private val authenticationInformationProvider = config.authenticationInformationProvider
    private val preferredLanguage = config.userPreferencesManager.locales
    
    override fun preProcess(request: Request, response: Response): RequestModel = RequestModel(request)
    
    override fun get(requestModel: RequestModel, response: Response): Optional<AuthenticationResult>
    {
        return handle(requestModel, response)
    }
    override fun post(requestModel: RequestModel, response: Response): Optional<AuthenticationResult>
    {
        // Strange but fine if the client wants to do a post to start the flow
        
        return handle(requestModel, response)
    }
    
    private fun handle(requestModel: RequestModel, response: Response): Optional<AuthenticationResult>
    {
        val authUrl = authenticationInformationProvider.fullyQualifiedAuthenticationUri
        val target = URL(authUrl.toURL(), "${authUrl.path}/${SignicatAuthenticatorPluginDescriptor.CALLBACK}")
        
        logger.debug("Redirecting to Signicat with the callback URL of {}", target)
        
        val method = when (country) {
            Country.SWEDEN -> "sbid"
            Country.DENMARK -> "nemid"
            Country.ESTONIA -> "esteid"
            Country.FINLAND -> "tupas"
            Country.NORWAY -> "nbid"
        }
        val env = when (environment) {
            Environment.PRE_PRODUCTION -> "preprod"
            Environment.PRODUCTION -> "id"
        }
        var id = "$method:"
        
        profile.ifPresent { id += it }
        
        if (preferredLanguage != null)
        {
            val bcp47languageTag = preferredLanguage.split(' ', limit = 1)[0] // Use only first
            
            try
            {
                val lang = Locale.forLanguageTag(bcp47languageTag).language.toLowerCase()
                
                id += ":$lang"
            }
            catch (_ : IllformedLocaleException)
            {
                logger.debug("The prefered language '$preferredLanguage' could not be parsed, so it will not be " +
                        "sent to Signicat")
            }
        }
        
        val location = "https://$env.signicat.com/std/method/$service?id=$id&target=$target"
        
        // Use a 303 in case this a POST request, so that the user agent is guaranteed (by compliance with HTTP) to
        // strip the body posted here before following the redirect.
        throw exceptionFactory.redirectException(location, RedirectStatusCode.SEE_OTHER)
    }
}