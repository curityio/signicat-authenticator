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

import com.signicat.document.v3.AuthenticationBasedSignature
import io.curity.identityserver.plugin.signicat.config.Country
import io.curity.identityserver.plugin.signicat.config.PredefinedEnvironment
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import io.curity.identityserver.plugin.signicat.descriptor.SignicatAuthenticatorPluginDescriptor
import io.curity.identityserver.plugin.signicat.signing.SigningClientFactory
import com.signicat.document.v3.CreateRequestRequest
import com.signicat.document.v3.DocumentAction
import com.signicat.document.v3.DocumentActionType
import com.signicat.document.v3.Method
import com.signicat.document.v3.SdsDocument
import com.signicat.document.v3.Signature
import com.signicat.document.v3.Task
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.http.HttpRequest
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.http.RedirectStatusCode
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.IllformedLocaleException
import java.util.Locale
import java.util.Optional

class RequestModel(request: Request)

class SignicatAuthenticatorRequestHandler(config: SignicatAuthenticatorPluginConfig)
    : AuthenticatorRequestHandler<RequestModel>
{
    private val logger: Logger = LoggerFactory.getLogger(SignicatAuthenticatorRequestHandler::class.java)
    private val exceptionFactory = config.exceptionFactory
    private val service = config.serviceName
    private val graphicsProfile = config.graphicsProfile
    private val country = config.country
    private val useSigning = config.useSigning
    private val authenticationInformationProvider = config.authenticationInformationProvider
    private val webserviceClientFactory = config.webServiceClientFactory
    private val environment = config.environment.customEnvironment.orElseGet {
        config.environment.standardEnvironment.map {
            when (it)
            {
                PredefinedEnvironment.PRE_PRODUCTION -> "preprod"
                PredefinedEnvironment.PRODUCTION     -> "id"
            // This and the other exceptional case below are guaranteed by the data model to never happen, but
            // this fact isn't know in the type system. So, these cases are handled to avoid bogus warnings,
            // but they will not occur.
                null                                 -> throw exceptionFactory.internalServerException(ErrorCode.CONFIGURATION_ERROR)
            }
        }.orElseThrow { throw exceptionFactory.internalServerException(ErrorCode.CONFIGURATION_ERROR) }
    }
    private val preferredLanguage = if (config.userPreferencesManager.locales != null)
    {
        val bcp47languageTag = config.userPreferencesManager.locales.split(' ', limit = 1)[0] // Use only 1st
        
        try
        {
            Optional.of(Locale.forLanguageTag(bcp47languageTag).language.toLowerCase())
        }
        catch (_: IllformedLocaleException)
        {
            logger.debug("The preferred language '$config.userPreferencesManager.locales' could not be parsed, " +
                    "so it will not be sent to Signicat")
            Optional.empty<String>()
        }
    }
    else Optional.empty()
    
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
        
        val location = if (useSigning.isPresent)
        {
            val (requestId, taskId) = getSigningInfo(environment, service, preferredLanguage, graphicsProfile)
        
            "https://$environment.signicat.com/std/docaction/$service?request_id=$requestId&task_id=$taskId"
        }
        else
        {
            val method = when (country)
            {
                Country.SWEDEN  -> "sbid"
                Country.DENMARK -> "nemid"
                Country.ESTONIA -> "esteid"
                Country.FINLAND -> "tupas"
                Country.NORWAY  -> "nbid"
            }
            var id = "$method:"
        
            graphicsProfile.ifPresent { id += it }
            preferredLanguage.ifPresent { id += ":it" }
        
            "https://$environment.signicat.com/std/method/$service?id=$id&target=$target"
        }
        
        // Use a 303 in case this a POST request, so that the user agent is guaranteed (by compliance with HTTP) to
        // strip the body posted here before following the redirect.
        throw exceptionFactory.redirectException(location, RedirectStatusCode.SEE_OTHER)
    }
    
    private fun getSigningInfo(env: String, serviceName: String, preferredLanguage: Optional<String>,
                               graphicsProfile: Optional<String>): Pair<String, String>
    {
        val sdsDocument = requestSessionDataStorageDocument(env, serviceName)
        val taskId = "task_1"
        val request = with(CreateRequestRequest()) {
            service = serviceName
            password = useSigning
                    // For this to throw, the presence of useSigning wasn't checked before. This is a logic error
                    // and should never happen.
                    .orElseThrow { throw exceptionFactory.internalServerException(ErrorCode.PLUGIN_ERROR) }
                    .secret
            request += with(com.signicat.document.v3.Request()) {
                clientReference = authenticationInformationProvider.fullyQualifiedAuthenticationUri.
                        path.reversed().split("/").first().reversed() // Authenticator ID
                
                preferredLanguage.ifPresent { language = it }
                graphicsProfile.ifPresent { profile = it }
                document += sdsDocument
                
                task += with(Task()) {
                    id = taskId
                    
                    documentAction += with(DocumentAction()) {
                        type = DocumentActionType.SIGN
                        documentRef = sdsDocument.id
                        this
                    }
                    authenticationBasedSignature += with(AuthenticationBasedSignature()) {
                        method += with(Method()) {
                            value = when (country)
                            {
                                Country.SWEDEN  -> "sbid"
                                Country.DENMARK -> "nemid"
                                Country.ESTONIA -> "esteid"
                                Country.FINLAND -> "tupas"
                                Country.NORWAY  -> "nbid"
                            }
                            this
                        }
                        this
                    }
                    this
                }
                this
            }
            this
        }
        
        val client = SigningClientFactory.create()
        val response = client.createRequest(request)
        
        return Pair(response.requestId.get(0), taskId)
    }
    
    private fun requestSessionDataStorageDocument(env: String, service: String): SdsDocument
    {
        val webServiceClient = webserviceClientFactory.create(URI.create("https://$env.signicat.com/doc/$service/sds"))
        val response = webServiceClient.request()
                .header("Authorization", "Basic ZGVtbzpCb25kMDA3") // TODO create from config
                .header("Content-Type", "text/plain;charset=utf8")
                .body(HttpRequest.fromString("test", StandardCharsets.UTF_8))
                .post()
                .response()
        
        if (response.statusCode() != 201)
        {
            throw exceptionFactory.externalServiceException("Could not create a document at the SDS service")
        }
        
        return with(SdsDocument()) {
            refSdsId = response.body(HttpResponse.asString())
            externalReference = "some_id"
            id = externalReference
            description = "This is a description"
            this
        }
    }
}