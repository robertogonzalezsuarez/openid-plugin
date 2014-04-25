/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.Failure;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.security.SecurityRealm;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.yadis.YadisResolver;
import org.openid4java.discovery.yadis.YadisResult;
import org.openid4java.util.HttpCache;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Augments other {@link SecurityRealm} by allowing login via OpenID.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class OpenIdLoginService extends FederatedLoginService {
    private final ConsumerManager manager;

    public OpenIdLoginService() throws ConsumerException {
        manager = new ConsumerManager();
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        manager.getDiscovery().setYadisResolver(new YadisResolver2());
    }

    @Override
    public String getUrlName() {
        return "openid";
    }

    public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
        return OpenIdUserProperty.class;
    }

    /**
     * Commence a login.
     */
    public HttpResponse doStartLogin(@QueryParameter String openid, @QueryParameter String openid_identifier, @QueryParameter final String from) throws OpenIDException, IOException {
        // if the script doesn't work, it'll submit 'openid_identifier'
        // <INPUT type=text NAME=openid/> is programmatically constructed
    	System.out.println("log1: doStartLogin de OpenIdLoginService con openId="+openid+ " y open_ididentifier="+openid_identifier+" y from="+from);
        if (openid==null)       openid = openid_identifier;

        return new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                IdentityImpl id = new IdentityImpl(identity);
                User u = id.signin();
                id.id.updateProfile(u);

                return HttpResponses.redirectToContextRoot();
            }
        }.doCommenceLogin();
    }

    public HttpResponse doFinish(StaplerRequest request) throws IOException, OpenIDException {
    	System.out.println("log1: doFinish de OpenIdLoginServise");
        OpenIdSession session = OpenIdSession.getCurrent();
        if (session==null)
            throw new Failure(Messages.OpenIdLoginService_SessionNotFound());
        return session.doFinishLogin(request);
    }

    public HttpResponse doStartAssociate(@QueryParameter String openid) throws OpenIDException, IOException {
        return new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                new IdentityImpl(identity).addToCurrentUser();
                return new HttpRedirect("onAssociationSuccess");
            }
        }.doCommenceLogin();
    }

    public class IdentityImpl extends FederatedLoginService.FederatedIdentity {
        private final Identity id;

        public IdentityImpl(Identity id) {
            this.id = id;
        }

        @Override
        public String getIdentifier() {
            return id.getOpenId();
        }

        @Override
        public String getNickname() {
            return id.getEffectiveNick();
        }

        @Override
        public String getFullName() {
            return id.getFullName();
        }

        @Override
        public String getEmailAddress() {
            return id.getEmail();
        }

        @Override
        public String getPronoun() {
            return "OpenID";
        }
    }
}
