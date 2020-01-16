#!/bin/bash

set -e

FUSIONAUTH_URL=http://fusionauth:9011
TMPDIR=$(dirname $BASH_SOURCE)/../tmp
mkdir -p $TMPDIR

if [ ! -r $TMPDIR/api.key ]; then

  curl -sS $FUSIONAUTH_URL/setup-wizard -H 'Content-Type: application/x-www-form-urlencoded' -d 'user.firstName=Test&user.lastName=Test&user.email=test%40example.com&user.password=test1234&passwordConfirm=test1234&__cb_acceptLicense=false&acceptLicense=true&__cb_addToNewsletter=false&timezone=America%2FChicago'

  curl -sSL -c $TMPDIR/cookies.txt -o $TMPDIR/login.html $FUSIONAUTH_URL/login

  CLIENT_ID=$(sed -E -n '/input type="hidden" name="client_id"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)
  TENANT_ID=$(sed -E -n '/input type="hidden" name="tenantId"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)
  STATE=$(sed -E -n '/input type="hidden" name="state"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/login.html)

  echo "Client ID: ${CLIENT_ID}"
  echo "Tenant ID: ${TENANT_ID}"

  curl -sSL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o /dev/null $FUSIONAUTH_URL/oauth2/authorize -H 'Content-Type: application/x-www-form-urlencoded' -d "client_id=${CLIENT_ID}&redirect_uri=%2Flogin&response_type=code&state=${STATE}&loginId=test%40example.com&password=test1234"

  curl -sSL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o $TMPDIR/add.html $FUSIONAUTH_URL/admin/api/add

  CSRF_TOKEN=$(sed -E -n '/input type="hidden" name="primeCSRFToken"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/add.html)
  API_KEY=$(sed -E -n '/input .* name="authenticationKey.id"/{ s/.*value="([^"]*)".*/\1/ p; }' $TMPDIR/add.html)

  echo "API Key: ${API_KEY}"

  curl -sSL -b $TMPDIR/cookies.txt -c $TMPDIR/cookies.txt -o /dev/null $FUSIONAUTH_URL/admin/api/add -H 'Content-Type: application/x-www-form-urlencoded' -H "Referer: $FUSIONAUTH_URL/admin/api/add" -d "primeCSRFToken=${CSRF_TOKEN}&authenticationKey.id=${API_KEY}"

  echo $TENANT_ID > $TMPDIR/tenant.id
  echo $API_KEY > $TMPDIR/api.key

else

  TENANT_ID=$(cat $TMPDIR/tenant.id)
  API_KEY=$(cat $TMPDIR/api.key)

fi

if [ ! -r $TMPDIR/user.json ]; then

  curl -sS -o $TMPDIR/user.json $FUSIONAUTH_URL/api/user?loginId=test@example.com -H "Authorization: ${API_KEY}"

fi

USER_ID=$(jq -r .user.id $TMPDIR/user.json)

APPLICATION_ID=31d7b8e8-f67e-4fb0-9c0b-872b793cda7a

if [ ! -r $TMPDIR/application.json ]; then

  curl -sS -o $TMPDIR/application.json $FUSIONAUTH_URL/api/application/$APPLICATION_ID -H 'Content-Type: application/json' -H "Authorization: ${API_KEY}" -d '{
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
        ],
        "generateRefreshTokens": true
      },
      "roles": [
        {
          "name": "admin"
        }
      ]
    }
  }'

  echo "Application ID: $APPLICATION_ID"

fi

if [ ! -r $TMPDIR/registration.json ]; then

  curl -sS -o $TMPDIR/registration.json $FUSIONAUTH_URL/api/user/registration/$USER_ID -H 'Content-Type: application/json' -H "Authorization: ${API_KEY}" -d "{
    \"registration\": {
      \"applicationId\": \"${APPLICATION_ID}\",
      \"roles\": [\"admin\"],
      \"username\": \"test\"
    }
  }"

  echo "Registration added"

fi
