# DCC Boxed DUIS Validation and Signing Tool

This command line tool is aimed at supporting [DCC Boxed][boxed] by simplifying
the XML signing and validation. DCC Boxed communicates using [DUIS][duis] (an
XML language defined in appendix AD of previous link), this tool signs DUIS
requests (i.e. adding an XML digital signature) and validating DUIS responses
(i.e. validating the XML digital signature and removing it). In addition, it
performs XSD validation.

DCC Boxed is a test tool. It is made available with a standard set of test SMKI
organisation certificates known as `ZAZ1`. So that it is possible to sign and
validate signatures, this tool ships with the same test certificates and
associated private keys. This same set of test certificates and private keys are
available with [GFI][gfi].

Finally, to reduce the work needed to sign the DUIS command the originator
counter will be automatically set to `System.currentTimeMillis` before the DUIS
is signed. This is to ensure that a strictly incrementing value is present in
each command and aligns with how DCC Boxed computes this internally for
DUIS commands it issues.

## Building

A standard maven build:

```
mvn package
```

This should result in a jar file being created in the `./target/` folder.

### Testing

To generate test coverage:

```
mvn clean jacoco:prepare-agent test jacoco:report
```

## Running

The tool can be run in one of two modes, Sign or Validate. In both cases 
the tool will print out logging information to `stderr`.

### Sign DUIS

To sign a DUIS message (XML without digital signature) from a file and print to
`stdout` the signed message (i.e. the XML with the digital signature) issue the
following:

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Sign message.xml
```

Or to read the DUIS message from `stdin`

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Sign -
```

For example, its possible to chain this with `cURL` to sign and submit a DUIS
command to a DCC Boxed instance:

```
java -cp xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Sign CS08_11.2_SUCCESS_REQUEST_DUIS.XML | curl http://dccboxed-server:8079/api/v1/serviceS -H 'Content-Type: application/xml' --data-binary -
```

#### Posix Return Codes

* **0**: Successful.
* **1** Generic `java` or OS error.
* **2** An exception raised in the app.
* **3** Missing public or private key material.
* **10** XSD validation failed. 

#### Advanced Signing

By default the tool will inspect the DUIS request to determine which private key
corresponds to the message to sign. This should cover the majority of the use
cases of the tool. However, it is also possible to provide the signers
credentials as command line arguments:

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Sign message.xml user.pem user.key
```

Here the `user.pem` and `user.key` are the associated certificate and private
key for the signer. These should both be of the correct format as defined by
SMKI, especially they need to be formatted as `pem` and the private key is both
EC prime256v1 and in the PKCS8 format. 

### Validate DUIS

To validate a DUIS message (XML with digital signature) from a file and print to
`stdout` the validated message (i.e. the XML without the digital signature)
issue the following:

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Validate message.xml
```

Or to read the DUIS message from `stdin`

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Validate -
```

#### Posix Return Codes

* **0**: Successful.
* **1** Generic `java` or OS error.
* **2** An exception raised in the app.
* **3** Missing public or private key material.
* **10** XSD validation or signature check failed. 

#### Advanced Validation

By default the tool will inspect the DUIS request to determine which certificate
corresponds to the sender of the message. This should cover the majority of the
use cases of the tool. However, it is also possible to provide the signers
credentials as command line arguments:

```
java -cp ./target/xmldsig-1.0-SNAPSHOT.jar uk.co.smartdcc.boxed.xmldsig.Validate message.xml user.pem
```

Here the `user.pem` is the associated users certificate. This should be of the
correct format as defined by SMKI, especially it need to be formatted as `pem`. 

## Contributing

Please feel welcome to report issues and/or submit pull requests.

If submitting pull requests for new features, please ensure it is aligned with
the tool and there is unit test coverage.

## Other Info

Copyright 2022, Smart DCC Limited, All rights reserved. Project is licensed under GLPv3.

[boxed]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/dcc-boxed/ "DCC Boxed"
[gfi]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/gfi/ "GFI"
[duis]: https://smartenergycodecompany.co.uk/the-smart-energy-code-2/ "Smart Energy Code"
