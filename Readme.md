

To get Code


http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&redirect_uri=http://127.0.0.1:8080/authorized


to get Access token


curl --location --request POST 'http://localhost:9000/oauth2/token' \
--header 'Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'code=M7W46Y9j1v-MhL78s-P_m2vywydHH-Y8GOCbvgHMDKcYfkEvh2yFpI92PIwbihQERe9jCx_M3HnwslenuIYsP4M7OXUwJIHTAj8hRoEtnLvMHH2PB9L3eckGTPc8jElv' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'redirect_uri=http://127.0.0.1:8080/authorized'