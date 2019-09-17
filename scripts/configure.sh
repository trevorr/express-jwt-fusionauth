#!/bin/bash

set -e

TMPDIR=$(dirname $BASH_SOURCE)/../tmp
mkdir -p $TMPDIR

if [ ! -r $TMPDIR/api.key ]; then

  curl -fs http://localhost:9011/setup-wizard -H 'Content-Type: application/x-www-form-urlencoded' -d 'user.firstName=Test&user.lastName=Test&user.email=test%40example.com&user.password=test1234&passwordConfirm=test1234&__cb_acceptLicense=false&acceptLicense=true&__cb_addToNewsletter=false&timezone=America%2FChicago'

  curl -fsL -c $TMPDIR/cookies.txt -o $TMPDIR/login.html http://localhost:9011/login

  CLIENT_ID=$(sed -E -n '/input type="hidden" name="client_id"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)
  TENANT_ID=$(sed -E -n '/input type="hidden" name="tenantId"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)
  STATE=$(sed -E -n '/input type="hidden" name="state"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)
  rm $TMPDIR/login.html

  echo "Client ID: ${CLIENT_ID}"
  echo "Tenant ID: ${TENANT_ID}"

  curl -fsL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o /dev/null http://localhost:9011/oauth2/authorize -H 'Content-Type: application/x-www-form-urlencoded' -d "client_id=${CLIENT_ID}&redirect_uri=%2Flogin&response_type=code&state=${STATE}&loginId=test%40example.com&password=test1234"

  curl -fsL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o $TMPDIR/add.html http://localhost:9011/admin/api/add

  CSRF_TOKEN=$(sed -E -n '/input type="hidden" name="primeCSRFToken"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/add.html)
  API_KEY=$(sed -E -n '/input .* name="authenticationKey.id"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/add.html)
  rm $TMPDIR/add.html

  echo "API Key: ${API_KEY}"

  curl -fsL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o /dev/null http://localhost:9011/admin/api/add -H 'Content-Type: application/x-www-form-urlencoded' -H 'Referer: http://localhost:9011/admin/api/add' -d "primeCSRFToken=${CSRF_TOKEN}&authenticationKey.id=${API_KEY}"
  rm $TMPDIR/cookies.txt

  echo $TENANT_ID > $TMPDIR/tenant.id
  echo $API_KEY > $TMPDIR/api.key

else

  TENANT_ID=$(cat $TMPDIR/tenant.id)
  API_KEY=$(cat $TMPDIR/api.key)

fi

if [ ! -r $TMPDIR/user.json ]; then

  curl -fs -o $TMPDIR/user.json http://localhost:9011/api/user?loginId=test@example.com -H "Authorization: ${API_KEY}"

fi

USER_ID=$(jq -r .user.id $TMPDIR/user.json)

APPLICATION_ID=31d7b8e8-f67e-4fb0-9c0b-872b793cda7a

if [ ! -r $TMPDIR/application.json ]; then

  curl -fs -o $TMPDIR/application.json http://localhost:9011/api/application/$APPLICATION_ID -H 'Content-Type: application/json' -H "Authorization: ${API_KEY}" -d '{
    "application": {
      "name": "Test Application",
      "jwtConfiguration": {
        "enabled": true,
        "refreshTokenTimeToLiveInMinutes": 43200,
        "timeToLiveInSeconds": 3600
      },
      "oauthConfiguration": {
        "clientSecret": "VYKsyjndsJ7lTnS2Z5vuz4SM-8Dvy1-4_yvqEoALMfY",
        "requireClientAuthentication": true,
        "authorizedRedirectURLs": [
          "http://localhost:3000/oauth"
        ],
        "enabledGrants": [
          "authorization_code",
          "refresh_token"
        ]
      },
      "roles": [
        {
          "name": "admin"
        }
      ]
    }
  }'

fi

if [ ! -r $TMPDIR/registration.json ]; then

  curl -fs -o $TMPDIR/registration.json http://localhost:9011/api/user/registration/$USER_ID -H 'Content-Type: application/json' -H "Authorization: ${API_KEY}" -d "{
  \"registration\": {
    \"applicationId\": \"${APPLICATION_ID}\",
    \"roles\": [\"admin\"],
    \"username\": \"test\"
  }
}
"

fi
