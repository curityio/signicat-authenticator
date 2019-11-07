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

package io.curity.identityserver.plugin.signicat.signing

import com.signicat.document.v3.DocumentEndPoint
import com.signicat.document.v3.DocumentService
import org.apache.commons.codec.CharEncoding
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.service.crypto.ClientKeyCryptoStore
import se.curity.identityserver.sdk.service.crypto.ServerTrustCryptoStore
import java.io.ByteArrayOutputStream
import java.util.Optional
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.xml.namespace.QName
import javax.xml.ws.BindingProvider
import javax.xml.ws.handler.MessageContext
import javax.xml.ws.handler.soap.SOAPHandler
import javax.xml.ws.handler.soap.SOAPMessageContext

class SigningClientFactory
{
    companion object
    {
        private val logger = LoggerFactory.getLogger(SigningClientFactory::class.java)
    
        // Generous timeouts; we only want to make sure that the requesting thread isn't consumed indefinitely.
        private const val CONNECT_TIMEOUT = 3000
        private const val REQUEST_TIMEOUT = 10000
    
        private const val JAXWS_PROPERTIES_SSL_SOCKET_FACTORY_INTERNAL = "com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory"
        private const val JAXWS_PROPERTIES_SSL_SOCKET_FACTORY = "com.sun.xml.ws.transport.https.client.SSLSocketFactory"
        private const val JAXWS_PROPERTIES_CONNECT_TIMEOUT_INTERNAL = "com.sun.xml.internal.ws.connect.timeout"
        private const val JAXWS_PROPERTIES_CONNECT_TIMEOUT = "com.sun.xml.ws.connect.timeout"
        private const val JAXWS_PROPERTIES_REQUEST_TIMEOUT_INTERNAL = "com.sun.xml.internal.ws.request.timeout"
        private const val JAXWS_PROPERTIES_REQUEST_TIMEOUT = "com.sun.xml.ws.request.timeout"
    
        fun create(environment: String, clientKeyCryptoStore: Optional<ClientKeyCryptoStore>,
                   trustStore: Optional<ServerTrustCryptoStore>): DocumentEndPoint
        {
            val client = DocumentService()
            val port = client.documentServiceEndPointPort
            val bindingProvider = port as BindingProvider
            val endpoint = "https://$environment/ws/documentservice-v3"
    
            // Override the endpoint in the WSDL with the configured endpoint
            logger.debug("Using Signing Service endpoint: $endpoint")
            
            bindingProvider.requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpoint)

            val sslContext = SSLContext.getInstance("TLS")
            var trustManagers : Array<TrustManager>? = null
            var keyManagers : Array<KeyManager>? = null

            trustStore.ifPresent {
                val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

                trustManagerFactory.init(it.asKeyStore)
                trustManagers = trustManagerFactory.trustManagers
            }

            clientKeyCryptoStore.ifPresent {
                val keyManagerFactory = KeyManagerFactory.getInstance("PKIX")
                
                keyManagerFactory.init(it.asKeyStore, it.keyStorePassword)
                
                keyManagers = keyManagerFactory.getKeyManagers()
            }

            if (trustManagers != null || keyManagers != null) {
                sslContext.init(keyManagers, trustManagers, null)
                val sslSocketFactory = sslContext.socketFactory

                bindingProvider.requestContext.put(JAXWS_PROPERTIES_SSL_SOCKET_FACTORY, sslSocketFactory)
                bindingProvider.requestContext.put(JAXWS_PROPERTIES_SSL_SOCKET_FACTORY_INTERNAL, sslSocketFactory)
            }

            bindingProvider.requestContext.put(JAXWS_PROPERTIES_CONNECT_TIMEOUT, CONNECT_TIMEOUT)
            bindingProvider.requestContext.put(JAXWS_PROPERTIES_CONNECT_TIMEOUT_INTERNAL, CONNECT_TIMEOUT)
            bindingProvider.requestContext.put(JAXWS_PROPERTIES_REQUEST_TIMEOUT, REQUEST_TIMEOUT)
            bindingProvider.requestContext.put(JAXWS_PROPERTIES_REQUEST_TIMEOUT_INTERNAL, REQUEST_TIMEOUT)
        
            if (logger.isTraceEnabled)
            {
                val binding = bindingProvider.binding
                val handlerChain = binding.handlerChain
            
                handlerChain += object : SOAPHandler<SOAPMessageContext>
                {
                    override fun getHeaders(): Set<QName>? = null
    
                    override fun handleMessage(mhc: SOAPMessageContext) = logMessage(mhc)
    
                    override fun handleFault(mhc: SOAPMessageContext) = logMessage(mhc)
    
                    override fun close(messageContext: MessageContext) = Unit
    
                    private fun logMessage(context: SOAPMessageContext) : Boolean
                    {
                        val soapMessage = context.message
        
                        return try
                        {
                            val outputStream = ByteArrayOutputStream()
            
                            soapMessage.writeTo(outputStream)
            
                            logger.trace(outputStream.toString(CharEncoding.UTF_8))
                            true
                        }
                        catch (ex: Exception)
                        {
                            logger.warn("Could not log SOAP message", ex)
                            false
                        }
                    }
                }
            
                binding.handlerChain = handlerChain
            }
        
            return port
        }
    }
}
