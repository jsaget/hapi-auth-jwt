# hapi-auth-jwt
JWT Auth Hapi plugin

// const HASH_KEY = require('crypto').randomBytes(256).toString('base64')




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
