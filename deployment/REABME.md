# Certificates Generation
openssl genrsa -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -signkey server.key -days 365 -out server.crt
- ./extensions:/opt/keycloak/providers/
- ./certs/server.crt:/opt/keycloak/conf/server.crt
- ./certs/server.key:/opt/keycloak/conf/server.key
env:
      KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/conf/server.crt
      KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/conf/server.key
      KC_HOSTNAME_URL: https://localhost:9443
      KC_HOSTNAME: localhost
ports:
- "9443:8443"

command:
  - start
  - --transaction-xa-enabled=false
