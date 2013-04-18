/*
 * Copyright, 2012-2013, SALESFORCE.com
 * All Rights Reserved
 * Company Confidential
 */
package net.davidbuccola.force.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.representation.Form;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

/**
 * The standard implementation of {@link OAuthConnector} that leverages Jersey for outbound communications.
 */
@Component("oauthConnector")
public class JerseyOAuthConnector implements OAuthConnector {
    private static final Logger log = LoggerFactory.getLogger(JerseyOAuthConnector.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final List<GrantedAuthority> AUTHORITIES = Arrays.asList(
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_USER"),
        (GrantedAuthority) new SimpleGrantedAuthority("ROLE_API_USER"));

    @Autowired
    private OAuthClientConfig clientConfig;

    @Override
    public String buildAuthorizeUri(String callbackUri, String state) {
        UriBuilder builder = UriBuilder.fromUri(clientConfig.getServerURL())
            .path("services/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", clientConfig.getClientId())
            .queryParam("redirect_uri", callbackUri);

        if (!StringUtils.isEmpty(clientConfig.getDisplay()))
            builder = builder.queryParam("display", clientConfig.getDisplay());
        if (!StringUtils.isEmpty(clientConfig.getPrompt()))
            builder = builder.queryParam("prompt", clientConfig.getPrompt());
        if (!StringUtils.isEmpty(state))
            builder = builder.queryParam("state", state);

        return builder.build().toString();
    }

    @Override
    public ForceAuthenticationToken getToken(String code, String callbackUri) {
        Client client = Client.create();
        try {
            Form form = new Form();
            form.add("code", code);
            form.add("grant_type", "authorization_code");
            form.add("client_id", clientConfig.getClientId());
            form.add("client_secret", clientConfig.getClientSecret());
            form.add("redirect_uri", callbackUri);

            InputStream jsonStream = client
                .resource(clientConfig.getServerURL())
                .path("services/oauth2/token")
                .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .post(InputStream.class, form);
            JsonNode jsonTree = objectMapper.readTree(jsonStream);

            ForceAuthenticationToken authenticationToken = new ForceAuthenticationToken(
                extractUserId(jsonTree.get("id").asText()),
                jsonTree.get("access_token").asText(),
                jsonTree.get("instance_url").asText(),
                AUTHORITIES);
            authenticationToken.setAuthenticated(true);
            return authenticationToken;

        } catch (UniformInterfaceException e) {
            String message = String.format("Problem with OAuth token request: %s", extractErrorMessage(e));
            throw new OAuthException(message, e);
        } catch (JsonProcessingException e) {
            String message = String.format("Problem with OAuth token response: %s", e.getMessage());
            log.error(message, e);
            throw new OAuthException(message, e);
        } catch (IOException e) {
            String message = String.format("Problem reading OAuth token response stream: %s", e.getMessage());
            log.error(message, e);
            throw new OAuthException(message, e);
        }
    }

    private static String extractUserId(String idUrlString) {
        Validate.notEmpty(idUrlString);
        return idUrlString.substring(idUrlString.lastIndexOf('/') + 1);
    }

    private String extractErrorMessage(UniformInterfaceException e) {
        try {
            InputStream jsonStream = e.getResponse().getEntity(InputStream.class);
            JsonNode jsonNode = objectMapper.readTree(jsonStream);

            return String.format("%s: %s", jsonNode.get("error").asText(), jsonNode.get("error_description").asText());
        } catch (JsonProcessingException e2) {
            return e.getMessage(); // Just use exception message
        } catch (IOException e2) {
            return e.getMessage(); // Just use exception message
        }
    }
}
