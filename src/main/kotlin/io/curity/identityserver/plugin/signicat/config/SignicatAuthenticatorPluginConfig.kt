package io.curity.identityserver.plugin.signicat.config

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.service.UserPreferenceManager

interface SignicatAuthenticatorPluginConfig : Configuration
{
    val userPreferenceManager : UserPreferenceManager
}
