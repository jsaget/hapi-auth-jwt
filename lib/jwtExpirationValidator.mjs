'use strict'

import moment from 'moment'
import remove from 'lodash/remove.js'

const tokens = []

export default class JwtExpirationValidator {
  constructor(options) {
    this.options = options
  }

  findJwt(tokenId) {
    const currentTimestamp = moment().unix()
    return tokens.find(({ jti, exp }) => jti === tokenId && exp > currentTimestamp)
  }

  removeJwt(tokenId) {
    console.log('ExpirationValidator.removeJwt - PArams', tokenId)
    remove(tokens, ({ jti }) => jti === tokenId)
    console.log('ExpirationValidator.removeJwt - Tokens', tokens)
  }

  addJwt(token) {
    console.log('ExpirationValidator.addJwt - params', token)
    tokens.push(token)
    console.log('ExpirationValidator.addJwt - Tokens', tokens)
  }

  jwtCleaner() {
    const currentTimestamp = moment().unix()

    remove(tokens, ({ exp }) => exp <= currentTimestamp)

    setTimeout(this.jwtCleaner.bind(this), this.options.cleanInterval).unref()
    console.log('cleaner -- Token cleaned')
  }
}
