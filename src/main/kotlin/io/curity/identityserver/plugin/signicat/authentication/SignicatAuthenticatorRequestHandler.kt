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

import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.http.HttpStatus
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import se.curity.identityserver.sdk.web.Response.ResponseModelScope.NOT_FAILURE
import se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel
import java.util.Optional
import java.util.Collections.emptyMap
import java.util.Collections.singletonMap

class SignicatAuthenticatorRequestHandler(config : SignicatAuthenticatorPluginConfig)
    : AuthenticatorRequestHandler<RequestModel>
{
    val userPreferenceManager = config.userPreferenceManager
    
    private object ViewDataKeys
    {
        internal val USERNAME = "_username"
    }
    
    override fun preProcess(request: Request, response: Response): RequestModel
    {
        // set the template and model for responses on the NOT_FAILURE scope
        response.setResponseModel(templateResponseModel(
                singletonMap<String, Any>(ViewDataKeys.USERNAME, userPreferenceManager.username),
                "authenticate/get"), NOT_FAILURE)
    
        // on request validation failure, we should use the same template as for NOT_FAILURE
        response.setResponseModel(templateResponseModel(emptyMap(), "authenticate/get"), HttpStatus.BAD_REQUEST)
    
        return RequestModel(request)
    }
    
    override fun get(requestModel: RequestModel, response: Response): Optional<AuthenticationResult>
    {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
    
    override fun post(requestModel: RequestModel, response: Response): Optional<AuthenticationResult>
    {
        // TODO: Start signing process or return
        
        return Optional.empty()
    }
}