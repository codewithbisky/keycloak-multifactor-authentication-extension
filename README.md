# Keycloak MultiFactor Rest API Provider

## Overview
Keycloak is an open source identity and access management solution. This codebase extends provisioning 2 Factor Authentication (2FA) through non-interactve API methods ✨ 

Our project extends Keycloak with a custom RealmResourceProvider,JpaProviders etc. This allows for 2FA via API calls.

## APIs


### Generate 2FA data for a user
Description: Generates 2FA data for a user to setup Totp on user's device.

Method: `GET`

Path: `http://localhost:8080/realms/<your-realm>/two-factor-auth/manage-2fa/{user_id}/totp/generate`

Response example: 
```json
{
    "encodedTotpSecret": "OZJU43ZUIN2VO4BZKBYEWMLBOEZUSQKL",
    "totpSecretQRCode": "iVBORw0KGgoAAAANSUhEUgAAAPYAAAD2AQAAAADNaUdlAAACmklEQVR4Xu2YPc6DMAyGXTEwcoTcpLkYEkhcrL1JjtCRAeHvfR1ABVVdvsEe6gFRP0Fy/Benol9lkavmLD9+1Zzlx6+as5C/ROT26lOrr0bne6elJYAMMfig+nwNhW946KS6dksyEIL30j6xCeVjlk5V7uDYUyTelBkeTUAjfmo0DoU+EHDJGo7v8ad/W8a/XaX/kB9efK+f5/vjQ3058Spj0lWQBFm1yB3IJAJH15GbTmW+g1vUBUXEdN32582tNaK0WdVoPaNYknJRDD7Qaix6sL4pc67fbPZ784au7QWmT2iNeLPl6ER7/J35gFh3E+rbkgBaZgI7URAOgzOzEqan+QYd7G9qEYXgkmD/IjX+0BbOD8m+CcFpKzj7N/NzUORnXRmEa50acvUqnJx3XQhOWzv07wcUKCLMh/V83vPTmaslJM7nBxZZ/wGfuJ3qX2/O/mhTF7i1Rquft/p25hxoMB/ao5jW+s/Rv7057G9Xxn9l6fCQhqen0nJcDMGt/9itZEwYDe04xOOIvzsXq2rEH1lp/YeXPE5iIbhqobawK+L+hJVIAmxn9683R8EAVa/SyROW09PPfX/OXHn0waF2oLTktcj3+Htz5Ge7FTn8LFwpHMKO+cubIyEJWNU6b6Vz6j/+POPAQ2k3jP9ikywOwSAcgvgv3IKwyFHaN+Ys0zUGt/4Nq8UuUeS4jh7x9+b16OutoHkTWLCIeznmH2dugkWsak6tvfCQoc9jcFY1bC30b9qv7u/3T28+8P8jU2Dqov3WGt/7jy/n/29EkGRVIxb/rIE4+g+bZOKkQ09jCKOE4jbkWH9UVtLJv558YPx5oOjI0u6ZpPY2xODwqzXsbEMOd5LrTLvZ78y/yY9fNWf58avmLP/mf9HIqC/AJ2L7AAAAAElFTkSuQmCC"
}
```
`encodedTotpSecret` can be used when it is not possible to scan a qr code.


### Submit 2FA data for a user
Description: Submits 2FA data for a user to enable Totp credential for user in KeyCloak.

Method: `POST`

Path: `http://localhost:8080/realms/<your-realm>/two-factor-auth/manage-2fa/{user_id}/totp/submit`

Request example:
```json
{
    "deviceName": "totp",
    "totpInitialCode": "709716",
    "encodedTotpSecret": "OZJU43ZUIN2VO4BZKBYEWMLBOEZUSQKL",
    "overwrite": true
}
```

Response: On success empty response with `204` status code will be returned.

Here `deviceName` refers to the device on which we want to enable 2FA. `totpInitialCode` refers to the initial
6-digit code taken from 2FA Application (Authy, Google authenticator) by user. `encodedTotpSecret` refers to the 
Totp secret that was received before by `generate-2fa` call. `overwrite` if set to true, overwrites existing 2FA data for
that particular device.

## License
Apache 2.0

