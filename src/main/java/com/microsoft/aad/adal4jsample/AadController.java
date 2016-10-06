/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 * 
 * All Rights Reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 * 
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4jsample;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.sun.glass.ui.mac.MacApplication;
import org.apache.log4j.Logger;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.microsoft.aad.adal4j.AuthenticationResult;

@Controller
@RequestMapping("/secure/aad")
public class AadController {


    private static Logger logger = Logger.getLogger(AadController.class);

    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String getDirectoryObjects(ModelMap model, HttpServletRequest httpRequest) {

        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session.getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception("AuthenticationResult not found in session."));
            return "/error";
        } else {
            String data;
            try {


                // Jwt roles stuffs
                RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

                // Give the JWK a Key ID (kid), which is just the polite thing to do
                rsaJsonWebKey.setKeyId("k1");

                JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                        .setSkipSignatureVerification()
                        .setRequireExpirationTime() // the JWT must have an expiration time
                        .setMaxFutureValidityInMinutes(300) // but the  expiration time can't be too crazy
                        .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                        .setExpectedIssuer("https://sts.windows.net/a279e29a-f562-4f31-bb25-54f58f3273f4/") // whom the JWT needs to have been issued by
                        .setSkipDefaultAudienceValidation()
                        .build(); // create the JwtConsumer instance


                JwtClaims jwtClaims = jwtConsumer.processToClaims(result.getIdToken());

                JWT jwt = JWTParser.parse(result.getIdToken());
                ReadOnlyJWTClaimsSet rr = jwt.getJWTClaimsSet();
                Map<String, Object>mapo =  rr.getAllClaims();
                Object hh = rr.getClaim("roles");



                @SuppressWarnings("unchecked")
                ArrayList<String> roles = (ArrayList<String>) jwtClaims.getClaimValue("roles");


                for(String role : roles) {
                    logger.info("role : " + role);
                }

                @SuppressWarnings("unchecked")
                ArrayList<String> groups = (ArrayList<String>) jwtClaims.getClaimValue("groups");


                for(String group : groups) {
                    logger.info("group : " + group);
                }

                data = this.getUsernamesFromGraph(result.getAccessToken(), session.getServletContext()
                        .getInitParameter("tenant"));
                System.out.println("data : " + data);
                model.addAttribute("users", data);
            } catch (Exception e) {
                model.addAttribute("error", e);
                return "error";
            }
        }
        return "/secure/aad";
    }

    /* this.getUserApplicationRoles(result.getAccessToken(), session.getServletContext()
                        .getInitParameter("tenant"));*/
    @Deprecated
    private String getUserApplicationRoles(String accessToken, String tenant) throws Exception {

        //get info of the logged in user - we are interested in Object ID
        String urlPath = "https://graph.windows.net/me?api-version=1.6";
        HttpURLConnection conn = getHttpURLConnection(accessToken, tenant, urlPath);
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
        logger.info("logged in user :  -> " + goodRespStr);
        int responseCode = conn.getResponseCode();
        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        JSONObject userJsonObject = JSONHelper.fetchDirectoryObjectJSONObject(response);
        User user = new User();
        JSONHelper.convertJSONObjectToDirectoryObject(userJsonObject, user);
        System.out.println(user.getObjectId());
        System.out.println(user.getUserPrincipalName());
        logger.info(user.getObjectId());
        logger.info(user.getUserPrincipalName());

        urlPath = "https://graph.windows.net/%s/users/" + user.getObjectId() + "/appRoleAssignments?api-version=1.6";
        conn = getHttpURLConnection(accessToken, tenant, urlPath);
        goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
        response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);

        JSONArray users  = JSONHelper.fetchDirectoryObjectJSONArray(response);

        JSONObject thisUserJSONObject = users.optJSONObject(1);
        System.out.println(thisUserJSONObject.get("resourceDisplayName"));


        logger.info("app roles assigned user :  -> " + goodRespStr);


        //urlPath = "https://graph.windows.net/%s/servicePrincipals?api-version=1.6&$filter=displayName+eq+'adal4jsamplevero'";
        urlPath = "https://graph.windows.net/%s/servicePrincipals?api-version=1.6&$filter=displayName+eq+'" + thisUserJSONObject.get("resourceDisplayName")  + "'";
        //urlPath = "https://graph.windows.net/%s/servicePrincipals?api-version=1.6";
        conn = getHttpURLConnection(accessToken, tenant, urlPath);
        goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
        response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);

        users  = JSONHelper.fetchDirectoryObjectJSONArray(response);

         thisUserJSONObject = users.optJSONObject(0);
        //JSONHelper.convertJSONObjectToDirectoryObject(thisUserJSONObject);
         System.out.println(thisUserJSONObject.get("appRoles"));
        System.out.println(thisUserJSONObject.get("resourceDisplayName"));

        logger.info("app roles for the web app :  -> " + goodRespStr);



        return null;
    }

    private String getUsernamesFromGraph(String accessToken, String tenant) throws Exception {
        String urlPath = "https://graph.windows.net/%s/users?api-version=2013-04-05";
        HttpURLConnection conn = getHttpURLConnection(accessToken, tenant, urlPath);
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);
        logger.info("goodRespStr -> " + goodRespStr);
        int responseCode = conn.getResponseCode();
        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        JSONArray users = new JSONArray();

        users = JSONHelper.fetchDirectoryObjectJSONArray(response);

        StringBuilder builder = new StringBuilder();
        User user = null;
        for (int i = 0; i < users.length(); i++) {
            JSONObject thisUserJSONObject = users.optJSONObject(i);
            user = new User();
            JSONHelper.convertJSONObjectToDirectoryObject(thisUserJSONObject, user);
            builder.append("User Principal Name : " + user.getUserPrincipalName() + "<br/>");
            builder.append("Job Title : " + user.getJobTitle() + "<br/>");
            builder.append("Department : " + user.getDepartment() + "<br/>");
            builder.append("<br/><br/>");
        }

        urlPath = "https://graph.windows.net/me?api-version=1.6";
        return builder.toString();
    }

    private HttpURLConnection getHttpURLConnection(String accessToken, String tenant, String urlPath) throws IOException {
        URL url = new URL(String.format(urlPath, tenant,
                accessToken));
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 3128));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);

        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("api-version", "2013-04-05");
        conn.setRequestProperty("Authorization", accessToken);
        conn.setRequestProperty("Accept", "application/json;odata=minimalmetadata");
        return conn;
    }


}
