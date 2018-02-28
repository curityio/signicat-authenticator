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
import io.curity.identityserver.plugin.signicat.config.PredefinedEnvironment
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import org.hibernate.validator.constraints.NotBlank
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.AttributeName
import se.curity.identityserver.sdk.attribute.AttributeValue
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
    private val isProd = config.environment.customEnvironment.isPresent ||
            config.environment.standardEnvironment.map { it == PredefinedEnvironment.PRODUCTION }.orElse(false)
    private val allSubjectAttributeNames = setOf(
            "age",
            "age-class",
            "bank.id",
            "bankid-no",
            "bankid-se",
            "buypass-id",
            "cn",
            "customer.id",
            "customer.id.plaintext",
            "customer.id.type",
            "customer.name",
            "date-of-birth",
            "dk.cpr",
            "ee.ik",
            "ee.serialnumber",
            "fi-hetu",
            "fi.hetu",
            "firstname",
            "fnr",
            "friendly-name",
            "gender",
            "given-name",
            "givenname",
            "hetu",
            "lastname",
            "middlename",
            "monetary-limit-amount",
            "monetary-limit-currency",
            "name",
            "national-id",
            "nationality",
            "nemid",
            "no.fnr",
            "phone",
            "pid",
            "plain-name",
            "satu",
            "sbid",
            "se.persnr",
            "security-level",
            "serialnumber",
            "subject-dn",
            "subject-serial-number",
            "surname",
            "telia",
            "unique-id"
    )
    
    init
    {
        synchronized(this)
        {
            if (!isProd)
            {
                SamlFacade.goIntoTestMode()
            }
        }
    }
    
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
        val configuration = Properties()
        
        if (isProd)
        {
            configuration.setProperty(ASSERTING_PARTY_DN, PROD_DN)
        }
        else
        {
            logger.trace("SAML response from Signicat: {}", requestModel.samlResponse)
            
            configuration.setProperty(ASSERTING_PARTY_DN, NON_PROD_DN)
        }
        
        val samlFacade = SamlFacade(configuration)
        val samlResponseData = samlFacade.readSamlResponse(requestModel.samlResponse, requestModel.uri)
        val subjectAttributes = mutableListOf<Attribute>()
        val contextAttributes = mutableListOf<Attribute>()
        
        for (attribute in samlResponseData.attributes)
        {
            val attributes = if (allSubjectAttributeNames.contains(attribute.name))
                subjectAttributes else contextAttributes
            
            val attributeName = if (attribute.name.contains('.'))
                AttributeName.of(attribute.name, "period-delimited") else AttributeName.of(attribute.name)
            
            val attributeValue = if (attribute.valueList.size == 1)
                AttributeValue.of(attribute.value) else AttributeValue.of(attribute.valueList)
            
            attributes.add(Attribute.of(attributeName, attributeValue))
        }
        
        return Optional.of(
                AuthenticationResult(
                        AuthenticationAttributes.of(
                                SubjectAttributes.of(samlResponseData.subjectName, Attributes.of(subjectAttributes)),
                                ContextAttributes.of(contextAttributes))))
    }
}