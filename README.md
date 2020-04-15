# hapi-auth-jwt
JWT Auth Hapi plugin


You must define a logger has `server.app.logger` with at least `info` method

You must register the `findUserByProvider` method in hapi server with server.method and specify the name used to register the method as value of `options.methods.findUserByProvider`

`findUserByProvider` = async(provider, {email, userId}) => {}
  If an user if found (and only 1), this method must return the user data object for jwt
  If more than 1 user found, throw an error.
  return null otherwise (or raise an error)

Options example:
```js
{
  methods: {
    findUserByProvider: async(provider, {email, userId}) => {}, // return user data for jwt if found (and only 1 user for this provider. Throw an error if more than 1 user found), null otherwise
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
```

To generate the hash key, you can use `require('crypto').randomBytes(256).toString('base64')`


```
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

```