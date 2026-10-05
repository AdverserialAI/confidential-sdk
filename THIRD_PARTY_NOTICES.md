# Third-party notices

## Encrypted HTTP Body Protocol reference implementation

The TypeScript SDK depends on
[ehbp](https://www.npmjs.com/package/ehbp) version 0.3.3 and the Python SDK
depends on [tinfoil-ehbp](https://pypi.org/project/tinfoil-ehbp/) version
0.3.2, both published by the
[Tinfoil Encrypted HTTP Body Protocol project](https://github.com/tinfoilsh/encrypted-http-body-protocol).
They are distributed under the MIT License. This SDK deliberately uses those
maintained reference implementations for interoperable request and streaming
response encryption rather than a private cryptographic wire format.

Please report security vulnerabilities privately to
[security@adverserial.ai](mailto:security@adverserial.ai).
