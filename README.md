# Signicat Authenticator Plug-in
 
[![Build Status](https://travis-ci.org/curityio/signicat-authenticator.svg?branch=master)](https://travis-ci.org/curityio/signicat-authenticator)

An authenticator that uses the Signicat signing service to do authentication

## Deployment

To deploy the plug-in and its dependencies during development, this one-liner can be used:

```bash
mvn install dependency:copy-dependencies \
    -DincludeScope=runtime \
    -DoutputDirectory=$IDSVR_HOME/lib/plugins/signicat && \
cp target/identityserver.plugins.authenticators.signicat-*.jar $IDSVR_HOME/lib/plugins/signicat
``` 