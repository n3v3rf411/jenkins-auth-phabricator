package com.wltandingan.jenkins.plugins.auth.phabricator;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.oauth.OAuthService;
import com.wltandingan.jenkins.plugins.auth.phabricator.models.ConduitResponse;
import com.wltandingan.jenkins.plugins.auth.phabricator.models.UserWhoami;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.stapler.*;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static com.github.scribejava.core.utils.OAuthEncoder.encode;
import static java.lang.String.format;

/**
 * @author Willie Loyd Tandingan
 * @since 1.0
 */
public class PhabricatorSecurityRealm extends SecurityRealm {

    private String clientID;
    private String clientSecret;
    private String hostUrl;
    private boolean allowUsersToSignup;

    @DataBoundConstructor
    public PhabricatorSecurityRealm(
            String hostUrl,
            String clientID,
            String clientSecret,
            boolean allowUsersToSignUp) {
        super();
        this.hostUrl = urlWithEndingSlash(hostUrl);
        this.clientID = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
        this.allowUsersToSignup = allowUsersToSignUp;
    }

    private static String urlWithEndingSlash(String url) {
        if (!url.endsWith("/")) {
            return url + "/";
        }
        return url;
    }

    @Override
    public boolean allowsSignup() {
        return allowUsersToSignup;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(String,String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                authentication -> {
                    if (authentication instanceof AnonymousAuthenticationToken)
                        return authentication;
                    throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                }
        );
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return "securityRealm/loggedOut";
    }

    private String buildOAuthRedirectUrl() {
        String rootUrl = Jenkins.get().getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(@QueryParameter String from, @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish;
        if (from != null) {
            redirectOnFinish = from;
        } else if (referer != null) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = Jenkins.get().getRootUrl();
        }

        final String callbackUrl = buildOAuthRedirectUrl();

        final OAuth20Service service = new ServiceBuilder(clientID)
                .apiSecret(clientSecret)
                .callback(callbackUrl)
                .build(new PhabricatorScribeApi(hostUrl, clientID, callbackUrl));

        return new OAuthSession(service) {

            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    final OAuth2AccessToken accessToken = getOAuth().getAccessToken(authorizationCode);

                    final UserWhoami user = requestUser(getOAuth(), accessToken);

                    final GrantedAuthority[] authorities =
                            new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY };

                    // logs this user in.
                    UsernamePasswordAuthenticationToken token =
                            new UsernamePasswordAuthenticationToken(user.getUserName(), "", authorities);
                    SecurityContextHolder.getContext().setAuthentication(token);

                    // update the user profile.
                    final User u = User.getById(token.getName(), allowUsersToSignup);
                    if (u == null) {
                        return HttpResponses.error(404, "Existing Jenkins user not found");
                    }

                    u.addProperty(new Mailer.UserProperty(user.getPrimaryEmail()));
                    u.setFullName(user.getRealName());

                    return new HttpRedirect(redirectOnFinish);

                } catch (OAuthException e) {
                    return HttpResponses.error(401, "Error from provider: " + e.getMessage());
                } catch (IOException | ExecutionException | InterruptedException e) {
                    return HttpResponses.error(500, e);
                }

            }
        }.doCommenceLogin();
    }

    private UserWhoami requestUser(final OAuthService scribe, final OAuth2AccessToken accessToken)
            throws InterruptedException, ExecutionException, IOException {
        final OAuthRequest userRequest = new OAuthRequest(Verb.GET,
                hostUrl + "api/user.whoami?access_token=" + encode(accessToken.getAccessToken()));
        final Response userResponse = scribe.execute(userRequest);

        if (!userResponse.isSuccessful()) {
            throw new IOException(format("Can not get Phabricator user profile. HTTP code: %s, response: %s",
                    userResponse.getCode(), userResponse.getBody()));
        }
        final String userResponseBody = userResponse.getBody();
        return ConduitResponse.parse(UserWhoami.class, userResponseBody).getResult();
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        final OAuthSession session = OAuthSession.getCurrent();

        if (session == null) {
            return HttpResponses.error(400, "This request is not part of an on-going OAuth flow. Please try logging in again.");
        }

        return session.doFinishLogin(request);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "Login with Phabricator";
        }
    }

}
