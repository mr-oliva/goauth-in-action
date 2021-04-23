# goath-in-action

Authentication server in [oauth-in-action-code](https://github.com/oauthinaction/oauth-in-action-code) is rewitten with Go.

This server is compatible with `client` and `protectedResource` in `oauth-in-action-code/exercises/ch-5-ex-2`

## Requires

- clone the original repository
  - [oauth-in-action-code](https://github.com/oauthinaction/oauth-in-action-code)

## How to Run

```
// under original repository
$ npm i
$ node client.js
$ node protectedResource.js

// under this repository
$ go run cmd/authorization/main.go <original repo's dir path>
```

Let's access http://localhost:9000/

## ToDo

- [x] Basic authentication server in OAuth 2.0
- [ ] Dynamic client registration (ch-12)
- [ ] Open ID Connect (ch-13)
