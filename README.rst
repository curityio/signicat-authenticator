Signicat Authenticator Plug-in
==============================
 
.. image:: https://travis-ci.org/curityio/signicat-authenticator.svg?branch=master
    :target: https://travis-ci.org/curityio/signicat-authenticator

An authenticator that uses the Signicat signing service to do authentication
This project provides an opens source Signicat Authenticator plug-in for the Curity Identity Server. This allows an administrator to add functionality to Curity which will then enable end users to login using their Signicat credentials -- or more exactly -- the credentials of some E-ID provider, like BankID or NemID. The app that integrates with Curity will be provided with all of the attributes released by the user at Signicat, including the user's personal number and other biographical information.

System Requirements
~~~~~~~~~~~~~~~~~~~

* Curity Identity Server 2.4.0 and `its system requirements <https://developer.curity.io/docs/latest/system-admin-guide/system-requirements.html>`_

Requirements for Building from Source
"""""""""""""""""""""""""""""""""""""

The source code is written entirely in `Kotlin <http://kotlinlang.org/>`_. It can be compiled using Maven 3. For this to succeed, however, the `Signicat Connector for Java <https://support.signicat.com/display/S2/Signicat+Connector+for+Java>`_ needs to be installed into a Maven repository which is accessible during compilation. The `POM <pom.xml>`_ may need to be updated depending on the Maven Coordinates (Group, Artifact, Version) used during installation. Refer to the `Maven guide for information about installing third-party JARs <https://maven.apache.org/guides/mini/guide-3rd-party-jars-local.html>`_. Once the Signicat Connector's JAR and its associated OpenSAML version are installed, the project can be compiled from a shell by issuing a command like this: ``mvn package``.

Installation
~~~~~~~~~~~~

To install this plug-in, either download a binary version available from the `releases section of this project's GitHub repository <https://github.com/curityio/signicat-authenticator/releases>`_ or compile it from source (as described above). If you compiled the plug-in from source, the package will be placed in the ``target`` subdirectory. The resulting JAR file or the one downloaded from GitHub needs to placed in the directory ``${IDSVR_HOME}/usr/share/plugins/signicat``. (The name of the last directory, ``signicat``, which is the plug-in group, is arbitrary and can be anything.) All of the dependent JAR files must be placed in this directory as well. These include:

* signicat-client-lib-4.0.1.jar
* signicat-opensaml-1.1-PATCH-6.jar
* commons-codec-1.10.jar
* xmlsec-1.5.8.jar

All of these JAR files can be obtained by downloading the `Signicat Connector for Java <https://support.signicat.com/display/S2/Signicat+Connector+for+Java>`_. Apache Commons Codec and Apache Santuario can be downloaded from Maven central or their respective project web sites.

.. note::

    The Signicat Connector ZIP file contains other JAR files as well (e.g., SLF4J, Apache Commons Logging, etc.). These are not required by this plug-in, but installing them should not adversely effect the plug-in either.

Once the plug-in and its dependencies are placed into the plug-in group directory, it will become available as soon as each node is restarted.

For a more detailed explanation of installing plug-ins, refer to the `Curity developer guide <https://developer.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation>`_.

Installing from Source
""""""""""""""""""""""

During development of the plug-in, it is very easy to copy the plug-in JAR and its dependencies with the following one-liner:

.. code:: bash

    mvn install dependency:copy-dependencies \
        -DincludeScope=runtime \
        -DoutputDirectory=$IDSVR_HOME/lib/plugins/signicat && \
    cp target/identityserver.plugins.authenticators.signicat-*.jar $IDSVR_HOME/lib/plugins/signicat

Because the server must be restarted after this, it can be quite tedious and time consuming. For that reason, it is better to use `Intellij's HotSwap capability <https://www.jetbrains.com/help/idea/reloading-classes.html>`_ to reload the classes after compilation. This will allow a developer to HotSwap changes without requiring a restart. If it fails to HotSwap some change, however, the above technique can be used.

Creating a Signicat Authenticator in Curity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to configure a new Signicat authenticator is using the Curity admin UI. The configuration for this can be downloaded as XML or CLI commands later, so only the steps to do this in the GUI will be described.

1. Go to the ``Authenticators`` page of the authentication profile wherein the authenticator instance should be created.
2. Click the ``New Authenticator`` button.
3. Enter a name (e.g., ``signicat1``). For production, this name needs to match the URI component in the callback URL whitelisted by Signicat.
4. For the type, pick the ``Signicat`` option:

    .. figure:: docs/images/criipto-authenticator-type-in-curity.png
        :align: center
        :width: 600px

5. On the next page, you can define all of the standard authenticator configuration options like any previous authenticator that should run, the resulting ACR, transformers that should executed, etc. At the bottom of the configuration page, the Signicat-specific options can be found.

    .. note::

        The Signicat-specific configuration is generated dynamically based on the `configuration model defined in the Kotlin interface <https://github.com/curityio/signicat-authenticator/blob/master/src/main/kotlin/io/curity/identityserver/plugin/signicat/config/SignicatAuthenticatorPluginConfig.kt>`_.

6. Certain required and optional configuration settings may be provided.
7. In the ``Client ID`` textfield, enter the client ID from the Criipto app configuration.
9. Also enter the matching ``Client Secret``.
10. If you wish to limit the scopes that Curity will request of Criipto, select the desired scopes from dropdown.

Once all of these changes are made, they will be staged, but not committed (i.e., not running). To make them active, click the ``Commit`` menu option in the ``Changes`` menu. Optionally enter a comment in the ``Deploy Changes`` dialogue and click ``OK``.

Once the configuration is committed and running, the authenticator can be used like any other.

License
~~~~~~~

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io <https://curity.io/>`_ for more information about the Curity Identity Server.

Copyright (C) 2018 Curity AB.