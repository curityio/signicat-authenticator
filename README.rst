Signicat Authenticator Plug-in
==============================
 
.. image:: https://curity.io/assets/images/badges/signicat-authenticator-quality.svg
       :target: https://curity.io/resources/code-examples/status/
       
.. image:: https://curity.io/assets/images/badges/signicat-authenticator-availability.svg
       :target: https://curity.io/resources/code-examples/status/

An authenticator that uses the Signicat login and signing services to do authentication.

This project provides an open source Signicat Authenticator plug-in for the Curity Identity Server. This allows an administrator to add functionality to Curity which will then enable end users to login using their Signicat credentials -- or more exactly -- the credentials of some E-ID provider, like BankID or NemID. The app that integrates with Curity will be provided with all of the attributes released by the user at Signicat, including the user's personal number and other biographical information.

System Requirements
~~~~~~~~~~~~~~~~~~~

Curity Identity Server 3.4.0 and `its system requirements <https://developer.curity.io/docs/latest/system-admin-guide/system-requirements.html>`_

Requirements for Building from Source
"""""""""""""""""""""""""""""""""""""

The source code is written entirely in `Kotlin <http://kotlinlang.org/>`_. It can be compiled using Maven 3.
For this to succeed, however, the `Signicat Connector for Java`_ and Signicat custom OpenSAML library needs to be installed into a Maven repository which is accessible during compilation.
To install these, download the jar-files to current directory and run the following commands:

.. code:: bash

   mvn org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file -Dfile=signicat-opensaml-1.1-PATCH-6.jar
   mvn org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file -Dfile=signicat-client-lib-4.0.1.jar

Installation
~~~~~~~~~~~~

To install this plug-in, either download a binary version available from the `releases section of this project's GitHub repository <https://github.com/curityio/signicat-authenticator/releases>`_ or compile it from source (as described above). If you compiled the plug-in from source, the package will be placed in the ``target/libs`` subdirectory. The resulting JAR file or the one downloaded from GitHub needs to placed in the directory ``${IDSVR_HOME}/usr/share/plugins/signicat``. (The name of the last directory, ``signicat``, which is the plug-in group, is arbitrary and can be anything.) All of the dependent JAR files must be placed in this directory as well. These include:

* signicat-client-lib-4.0.1.jar
* signicat-opensaml-1.1-PATCH-6.jar
* commons-codec-1.10.jar
* commons-logging-1.2.jar
* xmlsec-1.5.8.jar

All of these JAR files can be obtained by downloading the `Signicat Connector for Java`_. Apache Commons Codec and Apache Santuario can also be downloaded from Maven central or their respective project web sites.

.. note::

    The Signicat Connector ZIP file contains other JAR files as well (e.g., SLF4J). These are not required by this plug-in, and *should not* be installed. Including SLF4J in particular will cause an error on startup. If you get such an error, ensure that only the above dependencies are copied to the plug-in group directory.

Once the plug-in and its dependencies are placed into the plug-in group directory, it will become available as soon as each node is restarted.

For a more detailed explanation of installing plug-ins, refer to the `Curity developer guide <https://developer.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation>`_.

Installing from Source
""""""""""""""""""""""

During development of the plug-in, it is very easy to copy the plug-in JAR and its dependencies with the following one-liner:

.. code:: bash

    mvn dependency:copy-dependencies \
        -DincludeScope=runtime \
        -DoutputDirectory=$IDSVR_HOME/usr/share/plugins/signicat && \
        cp target/libs/identityserver.plugins.authenticators.signicat-*.jar $IDSVR_HOME/usr/share/plugins/signicat

Because the server must be restarted after this, it can be quite tedious and time consuming. For that reason, it is better to use `Intellij's HotSwap capability <https://www.jetbrains.com/help/idea/reloading-classes.html>`_ to reload the classes after compilation. This will allow a developer to HotSwap changes without requiring a restart. If it fails to HotSwap some change, however, the above technique can be used.

Creating a Signicat Authenticator in Curity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to configure a new Signicat authenticator is using the Curity admin UI. The configuration for this can be downloaded as XML or CLI commands later, so only the steps to do this in the GUI will be described.

1. Go to the ``Authenticators`` page of the authentication profile wherein the authenticator instance should be created.
2. Click the ``New Authenticator`` button.
3. Enter a name (e.g., ``signicat1``). For production, this name needs to match the URI component in the callback URL whitelisted by Signicat.
4. For the type, pick the ``Signicat`` option.
5. On the next page, you can define all of the standard authenticator configuration options like any previous authenticator that should run, the resulting ACR, transformers that should executed, etc. At the bottom of the configuration page, the Signicat-specific options can be found.

    .. figure:: docs/images/signicat-authenticator-type-in-curity.png
        :align: center
        :width: 600px

    Using these inputs, certain required and optional configuration settings may be provided.

    .. note::

        The Signicat-specific configuration is generated dynamically based on the `configuration model defined in the Kotlin interface <https://github.com/curityio/signicat-authenticator/blob/master/src/main/kotlin/io/curity/identityserver/plugin/signicat/config/SignicatAuthenticatorPluginConfig.kt>`_.

6. From the ``Method`` combobox, pick the country's kind of E-ID that should be used or type one of your own. For example, pick ``sbid`` to use Swedish BankID, ``nemid`` to use NemID, or ``cust`` for some custom E-ID method provided by Signicat.
7. Enter the ``Service Name`` that you have registered with Signicat or use the default of ``demo`` for testing.
8. From the ``Environment`` dropdown box, select either ``standard-environment`` or ``custom-environment``. The former should be used if you are not using a custom domain (e.g., ``signicat.example.com``). If not, then select ``standard-environment`` and pick either ``production`` or ``pre-production``. ``pre-production`` will cause certain test certificates to be used and warnings to be logged in the server log.
9. Optionally, enter the name of a `graphics profile <https://support.signicat.com/display/S2/Graphical+profiles%2C+fonts+and+styling>`_ in the ``Graphics Profile`` text field.
10. If signing should be used to perform authentication, toggle on the option ``Use Singing`` and enter the ``Secret`` used to identify your organization to the Signicat signing service.

Once all of these changes are made, they will be staged, but not committed (i.e., not running). To make them active, click the ``Commit`` menu option in the ``Changes`` menu. Optionally enter a comment in the ``Deploy Changes`` dialogue and click ``OK``.

Once the configuration is committed and running, the authenticator can be used like any other.

.. note::

    When using the authenticator with the Curity Security Token Service (i.e., the "OAuth server"), if the client application sends the OpenID-Connect-defined ``ui_locales`` request parameter, that will be passed to Signicat as the preferred language. Also, if a request has been made by some other client (in the same browser) using the ``ui_locales``, this preferred language will be propagated to Signicat even if the application does not explicitly provide it in the request.

License
~~~~~~~

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io <https://curity.io/>`_ for more information about the Curity Identity Server.

Copyright (C) 2018 Curity AB.

.. _Signicat Connector for Java: https://developer.signicat.com/documentation/other/signicat-connector-for-java/
