# gomitmproxy

Work in progress.

TODO:

* [X] Basic HTTP proxy without MITM
* [ ] Proxy
    * [ ] Expose APIs for the library users
    * [ ] Authentication
    * [ ] Unit tests
    * [ ] `certsCache` -- persistent storage
    * [X] Support HTTP CONNECT over TLS
    * [ ] Test plain HTTP requests inside HTTP CONNECT
    * [ ] Test memory leaks
    * [ ] Inspect TODOs
* [X] Basic MITM
    * [X] MITM exceptions
    * [X] Handle invalid server certificates properly (not just reset connections)
    * [X] Pass the most important tests on badssl.com/dashboard
    * [ ] OCSP revocation check (see [example](https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns))
    * [ ] Handle certificate authentication