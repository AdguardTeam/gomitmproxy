# gomitmproxy

Work in progress.

TODO:

* [X] Basic HTTP proxy without MITM
* [X] MITM
* [ ] MITM exceptions
* [X] Handle invalid server certificates properly (not just reset connections)
* [ ] Pass badssl.com/dashboard
* [ ] OCSP revocation check (see [example](https://stackoverflow.com/questions/46626963/golang-sending-ocsp-request-returns))
* [ ] Handle certificate authentication
* [ ] Unit tests
* [ ] Expose APIs for the library users
* [ ] Authentication
* [ ] `certsCache` -- persistent storage
* [ ] Support HTTP CONNECT over TLS
* [ ] Test plain HTTP requests inside HTTP CONNECT
* [ ] Test memory leaks
* [ ] Inspect TODOs