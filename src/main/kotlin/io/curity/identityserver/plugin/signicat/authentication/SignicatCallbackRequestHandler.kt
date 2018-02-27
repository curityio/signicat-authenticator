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

import com.signicat.services.client.saml.SamlFacade
import io.curity.identityserver.plugin.signicat.config.Environment
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import org.hibernate.validator.constraints.NotBlank
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.AttributeContainer
import se.curity.identityserver.sdk.attribute.Attributes
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes
import se.curity.identityserver.sdk.attribute.ContextAttributes
import se.curity.identityserver.sdk.attribute.SubjectAttributes
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.net.URL
import java.util.Optional
import java.util.Properties

class CallbackRequestModel(request: Request)
{
    @NotBlank(message = "validation.error.samlResponse.required")
    val samlResponse : String? = request.getFormParameterValueOrError("SAMLResponse")
    val uri: URL = URL(request.url)
}

class SignicatCallbackRequestHandler(config : SignicatAuthenticatorPluginConfig)
    : AuthenticatorRequestHandler<CallbackRequestModel>
{
    private val exceptionFactory = config.exceptionFactory
    private val logger: Logger = LoggerFactory.getLogger(SignicatCallbackRequestHandler::class.java)
    private val isProd = config.environment == Environment.PRODUCTION
    
    companion object
    {
        private const val ASSERTING_PARTY_DN = "asserting.party.certificate.subject.dn"
        private const val NON_PROD_DN = "CN=test.signicat.com/std, OU=Signicat, O=Signicat, L=Trondheim, ST=Norway, C=NO"
        private const val PROD_DN = "CN=id.signicat.com/std, OU=Signicat, O=Signicat, L=Trondheim, ST=Norway, C=NO"
    }
    
    override fun get(requestModel: CallbackRequestModel, response: Response): Optional<AuthenticationResult>
    {
        throw exceptionFactory.methodNotAllowed()
    }
    
    override fun preProcess(request: Request, response: Response): CallbackRequestModel
    {
        return CallbackRequestModel(request)
    }
    
    override fun post(requestModel: CallbackRequestModel, response: Response): Optional<AuthenticationResult>
    {
        logger.debug("SAML response from Signicat: {}", requestModel.samlResponse)
        
        val configuration = Properties()
        
        if (isProd)
        {
            configuration.setProperty(ASSERTING_PARTY_DN, PROD_DN)
        }
        else
        {
            configuration.setProperty(ASSERTING_PARTY_DN, NON_PROD_DN)
        }
        
        val samlFacade = SamlFacade(configuration)
        val samlResponseData = samlFacade.readSamlResponse(requestModel.samlResponse, requestModel.uri)
        val subjectAttributes = mutableListOf<Attribute>()
        val contextAttributes = ContextAttributes.empty()
        
        for (attribute in samlResponseData.attributes)
        {
            subjectAttributes.add(Attribute.of(attribute.name, attribute.valueList))
        }
        
        return Optional.of(
                AuthenticationResult(
                        AuthenticationAttributes.of(
                                SubjectAttributes.of(samlResponseData.subjectName, Attributes.of(subjectAttributes)),
                                contextAttributes)))
    }
}