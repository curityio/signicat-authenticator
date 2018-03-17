/*
 *  Copyright 2018 Curity AB
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