# An example OpenID Connect Relying Party Client

Supporting authorization code flow and third party initiated login

https://developer.okta.com/docs/concepts/auth-overview/#authorization-code-flow
https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin

## Setup

```sh
npm i
mv env-sample.json .env.json
```

1. Create a developer account at your favorite identity provider, e.g. https://developer.okta.com/
1. Set up a web client integration and get a client_id and client_secret
1. Configure the demo by editing `.env.json`

## Run

```sh
npm start
```

1. Log in to your Open ID Provider Org (issuer)
1.
