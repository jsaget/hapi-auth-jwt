'use strict'

import Boom from '@hapi/boom'
import Joi from '@hapi/joi'
import jwt from 'jsonwebtoken'
import moment from 'moment'
import uuid from 'uuid'
import extend from 'lodash/extend.js'
import pick from 'lodash/pick.js'

import JwtExpirationValidator from './jwtExpirationValidator.mjs'

// const HASH_KEY = require('crypto').randomBytes(256).toString('base64')

const options = {
  methods: {
    logger: console.log.bind(console),
    findUserByProvider: async(provider, userId) => {}, // return data for jwt if found, null otherwise
  },
  jwtExpirationValidator: {
    cleanInterval: 5 * 60 * 1000, // ms
  },
  jwt: {
    /// - hapi-auth-jwt2 options
    key: 'JWT_HASH_SECRET_KEY',
    // validate is automatically added
    verifyOptions: {
      ignoreExpiration: false,
      algorithms: 'HS256',
    },
    urlKey: false,
    cookieKey: false,
    payloadKey: false,
    headerKey: 'authorization', // we allow header only
    tokenType: 'Bearer',

    /// - custom attributs
    issuer: 'BOILERPLATE',
    duration: 15, // min
  },
}


const register = async (server, options = {}) => {
  const jwtExpValidator = new JwtExpirationValidator(options.jwtExpirationValidator)
  jwtExpValidator.jwtCleaner()

  const forgeJwt = async (provider, data, currentCredentials) => {
    const rawUser = await options.methods.findUserByProvider(provider, data)
    console.log('ForgeJwt -  findUserByProvider:' , rawUser)
    if (!rawUser) {
      return Boom.unauthorized('INVALID CREDENTIAL')
    }

    const user = pick(rawUser, ['_id', 'firstname', 'lastname', 'email', 'scope', 'group'])

    const newCredentials = extend({
      jti: uuid.v4(),
      iss: options.jwt.issuer,
      iat: moment().unix(),
      exp: moment().add(options.jwt.duration, 'minutes').unix(),
      scope: ['user'],
      provider: {
        name: provider,
        ...data,
      },
    }, user)
    console.log('newCredentials', newCredentials)

    if(currentCredentials) {
      jwtExpValidator.removeJwt(currentCredentials.jti)
    }
    jwtExpValidator.addJwt(newCredentials)

    return jwt.sign(newCredentials, options.jwt.key, { algorithm: options.jwt.verifyOptions.algorithms })
  }

  const validate = async(decoded, request, h) => {
    const currentDate = moment().unix()
    const storedToken = await jwtExpValidator.findJwt(decoded.jti)

    // TODO: test expiration
    if (decoded.iss === options.jwt.issuer && decoded.exp > currentDate && storedToken) {
      return { isValid: true, credentials: decoded }
    }

    return { isValid: false, credentials: null }
  }

  server.auth.strategy('jwt', 'jwt', extend(options.jwt, { validate }))
  server.auth.default({strategy: 'jwt', access: {scope: 'admin'}});

  server.route({
    method: 'GET',
    path: '/profile',
    options: {
      isInternal: true,
      auth: {
        access: {
          scope: ['auth'],
        },
      },
      validate: {
        query: Joi.object({
          provider: Joi.string(),
          userId: Joi.string(),
          email: Joi.string().email(),
        }).oxor('userId', 'email'),
      },
    },
    handler: async function(request, h) {
      console.log('Route /profile')
      if (!request.auth.isInjected) {
        return Boom.forbidden('you shall not pass human !!!')
        // throw new Error('you shall not pass human !!!')
      }

      const { provider, userId, email } = request.query
      return await forgeJwt(provider, { userId, email })
    }
  })

  server.route({
    method: 'GET',
    path: '/renew',
    options: {
      auth: {
        access: {
          scope: false,
        },
      },
    },
    handler: async function(request, h) {
      if (!request.auth.isAuthenticated) {
        // throw new Error('USer not logged')
        return Boom.unauthorized('NOT_LOGGED')
      }

      const { name, userId, email } = request.auth.credentials.provider
      return await forgeJwt(name, { userId, email }, request.auth.credentials)
    }
  })

  server.route({
    method: 'GET',
    path: '/revoke-token',
    options: {
      isInternal: true,
      auth: {
        access: {
          scope: ['auth'],
        },
      },
      validate: {
        query: Joi.object({
          tokenId: Joi.string(),
        }),
      },
    },
    handler: async (request, h) => {
      console.log('/revoke-token #1')
      const tokenId = request.query.tokenId
      console.log('/revoke-token #1.1', tokenId)
      jwtExpValidator.removeJwt(tokenId)
      console.log('/revoke-token #2')

      return h.response({ status: 'ok' })
    }
  })
}



const plugin = {
  name: 'auth-jwt',
  version: '1.0.0',
  dependencies: ['hapi-auth-jwt2'],
  once: true,
  register,
}

export default plugin



/*
1/ User appel /auth/login?username=toto&password=superpass
2/ Le plugin se signe un token avec comme scope auth et fait une requête sur /user/auth?type=user_password&data={username: toto, password: superpass}
3/ Le serveur répond par ex : {username: toto, scope: user, email: xxx, avatar: url}
4/ Le plugin rajoute à ces données les données techniques du token (issuer / expiration / etc) et génère le token
5/ Le plugin renvoie à l'user son token


En du coup ça marche bien aussi en oauth :
1/ L'user est dirigé sur la page /auth/oauth/google
2/ L'user est redirigé sur le serveur d'auth de google et s'authentifie
3/ Il est redirigé sur /auth/oauth/google avec plein de params en plus
4/ Le plugin d'auth fait une requête sur /user/auth?type=oauth_google&data={id: idgoogle}
5/ Le serveur répond par ex : {username: toto, scope: user, email: xxx, avatar: url}
6/ Le plugin rajoute à ces données les données techniques du token (issuer / expiration / etc) et génère le token
7/ Le plugin redirige l'user sur la page où il était avant en rajoutant ?token=token à l'URL
Tu peux enlever la charge tant que tu sais que c'est chez toi en utilisant server.inject au lieu de faire une requête HTTP full.
Tu pourrais mm mettre une config sur ton plugin pour lui dire si il faut faire du server.inject au lieu d'une requête.
Ou le décider en fct de l'URL donnée en param !!!
Si tu mets une URL complète, genre https://domain.com/user/auth, dans ce cas c'est requête HTTP(S), si tu mets juste un chemin, genre /user/auth, c'est server.inject qui est utilisé.
C'est assez sexy comme approche.
Comme ça, le plugin s'auto-optimise avec juste un petit test, c'est assez facile à mettre en place.

*/
