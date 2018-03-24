package com.signicat.services.client.saml;

import com.signicat.services.client.ScResponseException;
import com.signicat.services.client.ScSecurityException;
import com.signicat.services.client.ScSystemException;
import com.signicat.services.client.context.ScClientContext;

import java.net.URL;
import java.util.Properties;

public class SamlFacade
{
    public SamlFacade(Properties ignored)
    {
        throw new UnsupportedOperationException();
    }

    public SamlResponseData readSamlResponse(String ignored, URL ignored2) throws ScSystemException,
            ScSecurityException, ScResponseException
    {
        throw new UnsupportedOperationException();
    }

    public static void goIntoTestMode()
    {
        throw new UnsupportedOperationException();
    }

    public void setSamlKeystore(byte[] ignored)
    {
        throw new UnsupportedOperationException();
    }

    public ScClientContext getContext()
    {
        throw new UnsupportedOperationException();
    }
}
