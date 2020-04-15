'use strict'

import moment from 'moment'
import remove from 'lodash/remove.js'

const tokens = []

export default class JwtExpirationValidator {
  constructor(server, options) {
    this.server = server
    this.options = options
  }

  findJwt(tokenId) {
    const currentTimestamp = moment().unix()
    return tokens.find(({ jti, exp }) => jti === tokenId && exp > currentTimestamp)
  }

  removeJwt(tokenId) {
    this.server.app.logger.debug('ExpirationValidator.removeJwt - tokenId: ', tokenId)
    remove(tokens, ({ jti }) => jti === tokenId)
    this.server.app.logger.debug('ExpirationValidator.removeJwt - Tokens: ', tokens)
  }

  addJwt(token) {
    this.server.app.logger.debug('ExpirationValidator.addJwt - token: ', token)
    tokens.push(token)
    this.server.app.logger.debug('ExpirationValidator.addJwt - Tokens: ', tokens)
  }

  jwtCleaner() {
    const currentTimestamp = moment().unix()

    remove(tokens, ({ exp }) => exp <= currentTimestamp)

    setTimeout(this.jwtCleaner.bind(this), this.options.cleanInterval).unref()
    this.server.app.logger.info('cleaner -- Token cleaned')
  }
}
