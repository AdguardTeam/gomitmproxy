# gomitmproxy

Work in progress.

TODO:

* [X] Basic HTTP proxy without MITM
* [ ] Proxy
    * [X] Expose APIs for the library users
    * [ ] How-to doc
    * [X] Proxy-Authorization
    * [ ] Unit tests
    * [X] `certsCache` -- allow custom implementations
    * [X] Support HTTP CONNECT over TLS
    * [ ] Test plain HTTP requests inside HTTP CONNECT
    * [ ] Test memory leaks
    * [ ] Inspect TODOs
* [ ] MITM
    * [X] Basic MITM
    * [X] MITM exceptions
    * [X] Handle invalid server certificates properly (not just reset connections)
    * [X] Pass the most important tests on badssl.com/dashboard
    * [X] Handle certificate authentication
    * [ ] OCSP check (see [example](https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns))