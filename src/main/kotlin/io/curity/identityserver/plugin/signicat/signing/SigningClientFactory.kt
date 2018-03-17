package io.curity.identityserver.plugin.signicat.signing

import com.signicat.document.v3.DocumentEndPoint
import com.signicat.document.v3.DocumentService
import org.apache.commons.codec.CharEncoding
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
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
        private val CONNECT_TIMEOUT = 3000
        private val REQUEST_TIMEOUT = 10000
    
        private val JAXWS_PROPERTIES_SSL_SOCKET_FACTORY_INTERNAL = "com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory"
        private val JAXWS_PROPERTIES_SSL_SOCKET_FACTORY = "com.sun.xml.ws.transport.https.client.SSLSocketFactory"
        private val JAXWS_PROPERTIES_CONNECT_TIMEOUT_INTERNAL = "com.sun.xml.internal.ws.connect.timeout"
        private val JAXWS_PROPERTIES_CONNECT_TIMEOUT = "com.sun.xml.ws.connect.timeout"
        private val JAXWS_PROPERTIES_REQUEST_TIMEOUT_INTERNAL = "com.sun.xml.internal.ws.request.timeout"
        private val JAXWS_PROPERTIES_REQUEST_TIMEOUT = "com.sun.xml.ws.request.timeout"
        
        fun create(environment: String): DocumentEndPoint
        {
            val client = DocumentService()
            val port = client.documentServiceEndPointPort
            val bindingProvider = port as BindingProvider
            val endpoint = "https://$environment/ws/documentservice-v3"
    
            // Override the endpoint in the WSDL with the configured endpoint
            logger.debug("Using Signing Service endpoint: $endpoint")
            
            bindingProvider.requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpoint)

//        bindingProvider.requestContext.put(JAXWS_PROPERTIES_SSL_SOCKET_FACTORY, _sslSocketFactory)
//        bindingProvider.requestContext.put(JAXWS_PROPERTIES_SSL_SOCKET_FACTORY_INTERNAL, _sslSocketFactory)
        
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
