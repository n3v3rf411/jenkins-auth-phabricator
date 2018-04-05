package com.wltandingan.jenkins.plugins.auth.phabricator;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.Verb;

import static com.github.scribejava.core.utils.OAuthEncoder.encode;

/**
 * @author Willie Loyd Tandingan
 * @since 1.0
 */
public class PhabricatorScribeApi extends DefaultApi20 {

    private final String hostUrl;
    private final String clientId;
    private final String callback;

    public PhabricatorScribeApi(final String hostUrl, final String clientId, final String callback) {
        this.hostUrl = hostUrl;
        this.clientId = clientId;
        this.callback = callback;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return hostUrl + "oauthserver/token/";
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    public String getAuthorizationBaseUrl() {
        return hostUrl +
                "oauthserver/auth/?response_type=code&client_id=" + encode(clientId) +
                "&redirect_uri=" + encode(callback);
    }
}
