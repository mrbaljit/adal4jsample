package com.microsoft.aad.adal4jsample;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import org.json.JSONArray;
import org.json.JSONObject;

public class PublicClient {

    private final static String AUTHORITY = "https://login.windows.net/trvijayhotmail.onmicrosoft.com";
    private final static String CLIENT_ID = "ae3ce4db-4220-410b-b0d6-a95f82b26e75";
    private final static String SECRECT_KEY = "O4KkDw/+Zhcm7gPXUaHbblh+GUX7TZkjk/pcTPqNFIQ=";

    public static void main(String args[]) throws Exception {

            String username = "mrbaljit@live.com";
            String password = Constants.password;

            AuthenticationResult result = getAccessTokenFromUserCredentials(
                    username, password);
            System.out.println("Access Token - " + result.getAccessToken());
            System.out.println("Refresh Token - " + result.getRefreshToken());
            System.out.println("ID Token - " + result.getIdToken());

    }

    private static AuthenticationResult getAccessTokenFromUserCredentials(
            String username, String password) throws Exception {

        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 3128));

        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(AUTHORITY, false, service);
            context.setProxy(proxy);

            Future<AuthenticationResult> future = context.acquireToken(
                    "https://graph.windows.net", new ClientCredential(CLIENT_ID,
                            SECRECT_KEY), null);

            result = future.get();


            String urlPath = "";
            urlPath = "https://graph.windows.net/%s/users?api-version=1.6";
         //   urlPath = "https://graph.windows.net/me?api-version=1.6";
           //urlPath = "https://graph.windows.net/%s/directoryRoles?api-version=1.6";
             // urlPath = "https://graph.windows.net/%s/getObjectsByObjectIds?api-version=1.6";
            URL url = new URL(String.format(urlPath, "trvijayhotmail.onmicrosoft.com",
                    result.getAccessToken()));
            HttpURLConnection  conn = (HttpURLConnection) url.openConnection(proxy);
            //conn = (HttpURLConnection) url.openConnection(proxy);
            conn.setRequestProperty("api-version", "1.6");
            conn.setRequestProperty("Authorization",  result.getAccessToken());
            conn.setRequestProperty("Accept", "application/json;odata=minimalmetadata");
            String abcGoodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
            System.out.println("1>>>>>>>>> : " + abcGoodRespStr);

  /*          url = new URL(String.format(urlPath, "trvijayhotmail.onmicrosoft.com",
                    result.getUserInfo()));

            conn = (HttpURLConnection) url.openConnection(proxy);
            //conn = (HttpURLConnection) url.openConnection(proxy);
            conn.setRequestProperty("api-version", "1.6");
            conn.setRequestProperty("Authorization",  result.getAccessToken());
            conn.setRequestProperty("Accept", "application/json;odata=minimalmetadata");
             abcGoodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
            System.out.println(">>>>>>>>> : " + abcGoodRespStr);*/

  //"objectId": "ee8aa778-f801-44fd-b9ca-7ea5129ef4bd", for adal4jsamplevero

            //urlPath = "https://graph.windows.net/%s/users/%s/memberOf";
            //urlPath = "https://graph.windows.net/%s/users/%s";
            //urlPath = "https://graph.windows.net/%s/directoryRoles";
            //urlPath =  "https://graph.windows.net/%s/servicePrincipals/%s/appRoles?api-version=1.6"; //BEST - what are the app roles
            urlPath = "https://graph.windows.net/%s/servicePrincipals?api-version=1.6";
          // urlPath = "https://graph.windows.net/%s/servicePrincipals?$filter=displayName+eq+'adal4jsamplevero'";

           // urlPath = "https://graph.windows.net/%s/servicePrincipals/%s/appRoleAssignedTo?api-version=1.6"; //BEST
            //internal user - tester1@trvijayhotmail.onmicrosoft.com
            // urlPath = "https://graph.windows.net/%s/users/tester1@trvijayhotmail.onmicrosoft.com/appRoleAssignments?api-version=1.6"; //BEST
            //external user - mrbaljit@live.com, objectId
            urlPath = "https://graph.windows.net/%s/users/7e3ac7f3-75f2-4ff9-947d-8830714420db/appRoleAssignments?api-version=1.6"; //BEST
            url = new URL(String.format(urlPath, "trvijayhotmail.onmicrosoft.com", "ee8aa778-f801-44fd-b9ca-7ea5129ef4bd")); // BEST

           // https://graph.windows.net/contoso.com/servicePrincipals/a5e465e4-397d-4913-b232-15500d76ea09/appRoleAssignedTo?api-version=1.5

            conn = (HttpURLConnection) url.openConnection(proxy);
            //conn = (HttpURLConnection) url.openConnection(proxy);
            conn.setRequestProperty("api-version", "1.6");
            conn.setRequestProperty("Authorization",  result.getAccessToken());
            conn.setRequestProperty("Accept", "application/json;odata=minimalmetadata");
            abcGoodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
            System.out.println("3>>>>>>>>> : " + abcGoodRespStr);
            int responseCode = conn.getResponseCode();
            JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, abcGoodRespStr);
            JSONObject userJsonObject = JSONHelper.fetchDirectoryObjectJSONObject(response);
            System.out.println(userJsonObject.get("value"));



            JSONArray users  = JSONHelper.fetchDirectoryObjectJSONArray(response);

            JSONObject thisUserJSONObject = users.optJSONObject(1);
            System.out.println(thisUserJSONObject.get("resourceDisplayName"));


            System.out.println("ggg");
        //    IEnumerable<Claim> groups = User.FindAll("groups");

          /*  List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, upn )
                        , new Claim(ClaimTypes.Upn, upn )
                        , new Claim( "http://schemas.microsoft.com/identity/claims/objectidentifier", id_token.GetValue("oid").ToString() )
                        , new Claim(ClaimTypes.Surname, id_token.GetValue("family_name").ToString() )
                        , new Claim(ClaimTypes.GivenName, id_token.GetValue("given_name").ToString() )
                        , new Claim(ClaimTypes.Name, id_token.GetValue("unique_name").ToString() )
                        , new Claim("name", id_token.GetValue("name").ToString() )
                        , new Claim("iss", id_token.GetValue("iss").ToString() )
                        , new Claim("nbf", id_token.GetValue("nbf").ToString() )
                        , new Claim("exp", id_token.GetValue("exp").ToString() )
                        , new Claim("aud", id_token.GetValue("aud").ToString() )
                        , new Claim(ClaimTypes.NameIdentifier, id_token.GetValue("sub").ToString() )
                        , new Claim("ipaddr", id_token.GetValue("ipaddr").ToString() )
                        , new Claim("http://schemas.microsoft.com/identity/claims/tenantid", id_token.GetValue("tid").ToString() )
                        , new Claim("ver", id_token.GetValue("ver").ToString() )
            };
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Cookies");*/



          /*  ClaimsSet f = new ClaimsSet() {
                @Override
                public Object getClaim(String name) {
                    return super.getClaim(name);
                }
            };*/
       /*     ClaimsRequest claimsRequest = new ClaimsRequest();
            jwtClaimsSet.setJWTID();
            jwtClaimsSet.getAllClaims();*/


        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new ServiceUnavailableException(
                    "authentication result was null");
        }
        return result;
    }


}


