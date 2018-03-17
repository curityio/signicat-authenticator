package io.curity.identityserver.plugin.signicat.authentication

import io.curity.identityserver.plugin.signicat.config.PredefinedEnvironment
import io.curity.identityserver.plugin.signicat.config.SignicatAuthenticatorPluginConfig

internal val REQUEST_ID_SESSION_KEY = "REQUEST_ID_SESSION_KEY"
internal val USER_ID_SESSION_KEY = "USER_ID_SESSION_KEY"

internal fun withEnvironment(config: SignicatAuthenticatorPluginConfig): String =
        config.environment.customEnvironment.orElseGet {
            config.environment.standardEnvironment.map {
                when (it)
                {
                    PredefinedEnvironment.PRE_PRODUCTION -> "preprod.signicat.com"
                    PredefinedEnvironment.PRODUCTION     -> "id.signicat.com"
                    // This and the other exceptional case below are guaranteed by the data model to never happen, but
                    // this fact isn't know in the type system. So, these cases are handled to avoid bogus warnings,
                    // but they will not occur.
                    null -> throw IllegalStateException("Standard environment was configured with an unexpected value")
                }
            }.orElseThrow { throw IllegalStateException("Custom environment was not configured") }
        }