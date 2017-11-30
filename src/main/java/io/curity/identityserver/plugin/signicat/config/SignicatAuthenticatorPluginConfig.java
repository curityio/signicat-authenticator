package io.curity.identityserver.plugin.signicat.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.service.UserPreferenceManager;

public interface SignicatAuthenticatorPluginConfig extends Configuration
{
    UserPreferenceManager getUserPreferenceManager();

    @DefaultEnum("sweden")
    Country getCountry();
}
