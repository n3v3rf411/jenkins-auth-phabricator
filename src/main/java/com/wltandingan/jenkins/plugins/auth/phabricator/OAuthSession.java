package com.wltandingan.jenkins.plugins.auth.phabricator;

import com.github.scribejava.core.oauth.OAuth20Service;
import hudson.remoting.Base64;
import hudson.util.HttpResponses;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author Willie Loyd Tandingan
 * @since 1.0
 */
public abstract class OAuthSession {

    private final OAuth20Service oauth;
    private final String uuid = Base64.encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)).substring(0,20);

    OAuthSession(final OAuth20Service oauth) {
        this.oauth = oauth;
    }

    /**
     * Starts the login session.
     */
    HttpResponse doCommenceLogin() throws IOException {
        // remember this in the session
        Stapler.getCurrentRequest().getSession().setAttribute(SESSION_NAME, this);

        final Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("state", uuid);

        return new HttpRedirect(oauth.getAuthorizationUrl(additionalParams));
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     */
    HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        final String state = request.getParameter("state");

        if (state == null) {
            // user not sent from Phabricator
            return HttpResponses.redirectToContextRoot();
        }

        if (!uuid.equals(state)) {
            return HttpResponses.error(401, "State is invalid");
        }

        final String authorizationCode = request.getParameter("code");
        if (authorizationCode == null) {
            return HttpResponses.error(404, "Missing authorization code");
        }

        return onSuccess(authorizationCode);
    }

    protected OAuth20Service getOAuth() {
        return oauth;
    }

    protected abstract HttpResponse onSuccess(String authorizationCode) throws IOException;


    /**
     * Gets the {@link OAuthSession} associated with HTTP session in the current extend.
     */
    public static OAuthSession getCurrent() {
        return (OAuthSession) Stapler.getCurrentRequest().getSession().getAttribute(SESSION_NAME);
    }

    private static final String SESSION_NAME = OAuthSession.class.getName();

}
