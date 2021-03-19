# Roadmap

- catch await errors
- handle login_required and consent_required errs from auth
- customLoginPromptUrl for each provider integration
- customConsentPromptUrl for each provider integration
- support relative target_link_uri
- add PKCE 'pixy'
- expired session (after idle)
- use string tmpl literals for error
- cache jwks?
- demo access_token protected route
- pass in config so it can be consumed as a lib or sub microservice
- work out how to setup session for production
- try against multiple providers, e.g. auth0, okta
- replace some manual work w/pkgs like the auth0 stuff
