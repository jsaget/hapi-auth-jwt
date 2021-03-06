'use strict'

import Boom from '@hapi/boom'
import Joi from '@hapi/joi'
import jwt from 'jsonwebtoken'
import moment from 'moment'
import uuid from 'uuid'
import extend from 'lodash/extend.js'
import pick from 'lodash/pick.js'

import JwtExpirationValidator from './jwtExpirationValidator.mjs'

const schemaOptions = Joi.object({
  methods: Joi.object({
    findUserByProvider: Joi.string().required,
  }),
  jwtExpirationValidator: Joi.object({
    cleanInterval: Joi.number().min(1000).required(),
  }),
  jwt: Joi.object({
    key: Joi.string().required(),
    verifyOptions: Joi.object({
      ignoreExpiration: Joi.boolean(),
      algorithms: Joi.string(),
      urlKey: Joi.boolean(),
      cookieKey: Joi.boolean(),
      payloadKey: Joi.boolean(),
      headerKey: Joi.string(),
      tokenType: Joi.string(),

      issuer: Joi.string().required(),
      duration: Joi.number().required(),
    }),
  }),
})

const register = async (server, options = {}) => {
  schemaOptions.validate(options)

  const jwtExpValidator = new JwtExpirationValidator(server, options.jwtExpirationValidator)
  jwtExpValidator.jwtCleaner()

  const forgeJwt = async (provider, data, currentCredentials) => {
    const rawUser = await server.methods[options.methods.findUserByProvider](provider, data)

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
  server.auth.default({strategy: 'jwt', access: { scope: 'admin' }})

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
      if (!request.auth.isInjected) {
        throw Boom.forbidden('you shall not pass human !!!')
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
        throw Boom.unauthorized('NOT_LOGGED')
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
      const tokenId = request.query.tokenId
      jwtExpValidator.removeJwt(tokenId)

      return h.response({ status: 'ok' })
    }
  })
}

const plugin = {
  name: 'hapi-auth-jwt',
  version: '1.0.0',
  dependencies: ['hapi-auth-jwt2'],
  once: true,
  register,
}

export default plugin
