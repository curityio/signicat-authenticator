package io.curity.identityserver.plugin.signicat.authentication

import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.util.Optional

class SignicatAuthenticatorRequestHandler : AuthenticatorRequestHandler<RequestModel>
{
    override fun preProcess(p0: Request?, p1: Response?): RequestModel
    {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
    
    override fun get(p0: RequestModel?, p1: Response?): Optional<AuthenticationResult>
    {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
    
    override fun post(p0: RequestModel?, p1: Response?): Optional<AuthenticationResult>
    {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}