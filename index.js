/**
 * An example OpenID Connect Relying Party Client
 * Supporting authorization code flow and third party initiated login
 * https://developer.okta.com/docs/concepts/auth-overview/#authorization-code-flow
 * https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
 */
const cryptoRandomString = require('crypto-random-string')
const fetch = require('node-fetch')
const express = require('express')
const bodyParser = require('body-parser')
const session = require('express-session')
const jwt = require('jsonwebtoken')
const jwkToPem = require('jwk-to-pem')

// CONFIG
const environment = process.env.NODE_ENV || 'development'
const appConfig = require('./.env.json')[environment] // NOTE: don't commit .env.json file to VCS!
const defaultAuthNReqParams = {
  response_type: 'code',
  response_mode: 'form_post',
  scope: 'openid email offline_access', // offline_access scope so we can obtain a refresh_token
  prompt: 'none' // no auto prompt! support configurable third party login prompt w/frame busting
}
const defaultTokenReqParams = {
  grant_type: 'authorization_code'
}
// destructure
const {
  baseUrl,
  sessionSecret,
  oauth2: {
    initiateLoginPath,
    redirectPath,
    defaultTargetLinkUrl,
    clientInfoByProvider
  }
} = appConfig

// SERVER
const app = express()
const port = 3000

// MIDDLEWARE
app.use(bodyParser.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded
app.use(session({ secret: sessionSecret })) // NOTE: in-memory session is not for production!

// ROUTES
app.get(initiateLoginPath, async (req, res) => {
  if (!isValidLoginRequest(req, appConfig)) {
    res.sendStatus(400)
    return
  }

  const issuer = req.query.iss
  const targetLinkUrl = toAbsUrl(
    req.query.target_link_uri || defaultTargetLinkUrl, baseUrl
  )

  const providerConfig = await fetchProviderConfig(issuer)
  const nonce = getRandomString() // mitigate replay attacks with a nonce stored in session
  const stateId = getRandomString()
  const state = {
    issuer: issuer,
    providerConfig: providerConfig,
    targetLinkUrl: targetLinkUrl,
    authNReqParams: Object.assign(
      {},
      defaultAuthNReqParams,
      {
        client_id: clientInfoByProvider[issuer].clientId,
        redirect_uri: toAbsUrl(redirectPath, baseUrl),
        nonce: nonce,
        state: stateId
      }
    )
  }

  req.session[stateId] = state // persist state so callback handler can access it

  // When making requests to the authorization_endpoint, the browser (user agent) should be
  // redirected to the endpoint. Also, you can't use AJAX with this endpoint.
  res.redirect(302, renderAuthNReqUrl(
    providerConfig,
    state.authNReqParams
  ))
})

app.post(redirectPath, async (req, res) => {
  if (!isValidCallbackRequest(req)) {
    res.sendStatus(400)
    return
  }

  const stateId = req.body.state
  let error = req.body.error

  if (!error) {
    const state = req.session[stateId]
    const clientInfo = clientInfoByProvider[state.issuer]
    const authZCode = req.body.code

    // get tokens && keys
    const tokensAndKeys = await Promise.all([
      fetchTokens(state, clientInfo, authZCode),
      fetchKeys(state, clientInfo)
    ])

    // destructure
    const [
      { id_token: idToken, access_token: accessToken, refresh_token: refreshToken },
      { keys: jwks }
    ] = tokensAndKeys

    // decode & verify idToken
    const decodedIdToken = jwt.decode(idToken, { complete: true })
    const verifyOptions = {
      algorithms: state.providerConfig.id_token_signing_alg_values_supported,
      nonce: state.nonce,
      issuer: state.issuer,
      audience: clientInfo.clientId
    }
    let verifiedIdToken
    jwks.some(jwk => {
      if (jwk.kid === decodedIdToken.header.kid) {
        const pem = jwkToPem(jwk)
        try {
          verifiedIdToken = jwt.verify(idToken, pem, verifyOptions)
          error = null // clear error if decode worked
          return true
        } catch(e) {
          error = e
        }
      }
    })

    if (verifiedIdToken) {
      // TODO: remove these logs, they are for demo purposes only
      console.log('id_token claims', verifiedIdToken)
      console.log('access_token', accessToken)
      console.log('refresh_token', refreshToken)

      const sid = await createLocalSession(verifiedIdToken.email)
      const sidCookieOptions = {
        // TODO: set secure true, false for demo purposes only
        secure: false,
        httpOnly: true,
        sameSite: 'lax'
      }

      // redirect
      res.cookie('sid', sid, sidCookieOptions)
      res.redirect(302, state.targetLinkUrl)
    } else {
      // error = 'Invalid token kid'
    }

  }

  if (error) {
    // TODO: return page with link to login prompt page (target=_top) and error description
    res.status(403).send(error)
  }

  // remove state
  req.session[stateId] = null
})

// TODO: Remove this route, here for demo purposes only
app.get('/*', (req, res) => res.send(
  Object.keys(clientInfoByProvider).map(prov => {
    const url = `${initiateLoginPath}?iss=${prov}`
    return `<a href=${url}>${url}</a><br>`
  }).join('')
))

// STARTUP
app.listen(port, () => console.log(`Example app listening on port ${port}!`))

async function createLocalSession(email) {
  // TODO: THIS IS WHERE YOU DO YOUR BIZ
  const sid = 'fakesid-0123456789'
  return sid
}

// UTILS
async function fetchProviderConfig(issuer) {
  const url = toAbsUrl('/.well-known/openid-configuration', issuer)
  const resp = await fetch(url)
  return await resp.json()
}

function fetchKeys(state, clientInfo) {
  const params = { client_id: clientInfo.client_id }
  const url = `${state.providerConfig.jwks_uri}?${toReqParams(params)}}`
  return fetch(url).then(res => res.json())
}

function fetchTokens(state, clientInfo, authZCode) {
  return fetch(state.providerConfig.token_endpoint, {
    method: 'post',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${btoa(`${clientInfo.clientId}:${clientInfo.clientSecret}`)}`
    },
    body: toReqParams(Object.assign(
      {},
      defaultTokenReqParams,
      {
        redirect_uri: state.authNReqParams.redirect_uri,
        code: authZCode
      }
    ))
  }).then(res => res.json())
}

function btoa(str) {
  return Buffer.from(str).toString('base64')
}

function isValidLoginRequest(req, appConfig) {
  return appConfig.oauth2.clientInfoByProvider[req.query.iss] && // validate issuer
    // validate optional target URL
    (req.query.target_link_uri ? req.query.target_link_uri.startsWith(appConfig.baseUrl) : true)
}

function renderAuthNReqUrl(providerConfig, authNReqParams) {
  return `${providerConfig.authorization_endpoint}?${toReqParams(authNReqParams)}`
}

function isValidCallbackRequest(req) {
  const stateId = req.body.state
  return req.session[stateId] != null // validate state
}

function toReqParams(obj) {
  return Object.entries(obj).reduce(
    (params, [key, value]) => (params.append(key, value), params),
    new URLSearchParams()
  ).toString()
}

function toAbsUrl(url, base) {
  return (new URL(url, base)).toString()
}

function getRandomString() {
  return cryptoRandomString({length: 64, type: 'url-safe'})
}
