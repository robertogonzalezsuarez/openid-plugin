package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.util.HttpClientFactory;
import org.openid4java.util.ProxyProperties;

import sun.tools.tree.SuperExpression;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * {@link OpenIdSsoSecurityRealm} with Google Apps.
 *
 * @author Kohsuke Kawaguchi
 */
public class GoogleAppSsoSecurityRealm extends OpenIdSsoSecurityRealm {
    public final String domain;
    public String[] domains;
    public boolean multipleDomains;

    @DataBoundConstructor
    public GoogleAppSsoSecurityRealm(String domain) throws IOException, OpenIDException {
       	super("https://www.google.com/accounts/o8/site-xrds?hd="+domain.replace("//s","").split(",")[0]);
        String googleURL = "https://www.google.com/accounts/o8/site-xrds?hd=";
        this.domain = domain;
        String multipleDomains = this.domain.replace("//s", ""); //delete white spaces
        String[] multipleDomainsArray = multipleDomains.split(","); //create the list of domains
        int i = 0;
        if (multipleDomainsArray.length>1) {
        	//must concatenate all the domains with the google url
        	String[] endpointsProv = new String[multipleDomainsArray.length];
//        	this.domains = multipleDomainsArray;
        	System.arraycopy( multipleDomainsArray, 0, endpointsProv, 0, multipleDomainsArray.length );//copy the array (value copy)
        	for (i=0; i<multipleDomainsArray.length;i++)
        	{
        		multipleDomainsArray[i] = googleURL+ multipleDomainsArray[i];
        	}
        	this.domains = endpointsProv;
        	System.out.println("log1: Now domains0 are:"+this.domains[0]+" and multipleArray0 is :" + multipleDomainsArray[0]);
        	this.multipleDomains= true;
        	multipleOpenIdSsoSecurityRealm(multipleDomainsArray);
        }
        else
        {
    
        	this.multipleDomains= false;
        	this.multipleEndpoints=false;
        }
        
    }

    @Override
    protected ConsumerManager createManager() throws ConsumerException {
        final Hudson instance = Hudson.getInstance();
        if (instance.proxy != null) {
            ProxyProperties props = new ProxyProperties();
            props.setProxyHostName(instance.proxy.name);
            props.setProxyPort(instance.proxy.port);
            props.setUserName(instance.proxy.getUserName());
            props.setProxyHostName(instance.proxy.getPassword());
            HttpClientFactory.setProxyProperties(props);
        }
        ConsumerManager m = new ConsumerManager();
        System.out.println("log1: createManager de GoogleApp");
        m.setDiscovery(new Discovery() {
            /**
             * See http://www.slideshare.net/timdream/google-apps-account-as-openid for more details
             * why this is needed. Basically, once Google reports back that the user is actually http://mycorp.com/openid?id=12345,
             * the consumer still needs to try to resolve this ID to make sure that Google didn't return a bogus address
             * (say http://whitehouse.gov/barack_obama). This fails unless the web server of mycorp.com handles
             * GET to http://mycorp.com/openid?id=12345 properly, (which it doesn't most of the time.)
             *
             * The actual resource is in https://www.google.com/accounts/o8/user-xrds?uri=http://mycorp.com/openid?id=12345
             * so does Yadris lookup on that URL and pretend as if that came from http://mycorp.com/openid?id=12345
             */
            @Override
            public List discover(Identifier id) throws DiscoveryException {
             
            	System.out.println("log1: discover del createManager de GoogleApp VERIFICANDO id.getIdentifier:"+id.getIdentifier()+ " y domain ="+domain + " y el id=" + id.toString());//no entra en caso de googleapp
            	boolean startsWithDomain = false;
            	//check all the domains
            	for (String dom : domains) {
            		System.out.println("log1: checking domain - "+dom);
            		if (id.getIdentifier().startsWith("http://"+dom+'/')) {
            			startsWithDomain = true;
            			System.out.println("log1: the domain is correct: " + dom);
            		}
            	}
            	if (id instanceof UrlIdentifier && startsWithDomain)
            	{
            		
                //if (id.getIdentifier().startsWith("http://"+domain+'/') && id instanceof UrlIdentifier) {
                	System.out.println("log1: LOGEANDO CON DOMAIN: "+domain+ " Y la ID es:"+id.getIdentifier());
                    String source = "https://www.google.com/accounts/o8/user-xrds?uri=" + id.getIdentifier();
                    List<DiscoveryInformation> r = super.discover(new UrlIdentifier(source));
                    List<DiscoveryInformation> x = new ArrayList<DiscoveryInformation>();
                    System.out.println("log1: DISCOVER linea 112 SecurityRealm");
                    for (DiscoveryInformation discovered : r) {
                        if (discovered.getClaimedIdentifier().getIdentifier().equals(source)) {
                            discovered = new DiscoveryInformation(discovered.getOPEndpoint(),
                                    id,
                                    discovered.getDelegateIdentifier(),
                                    discovered.getVersion(),
                                    discovered.getTypes()
                            );
                        }
                        x.add(discovered);
                    }
                    return x;
                }
     
            	System.out.println("LOGEANDO     return super.discover(id);");
            	return super.discover(id);
            }
        });
        return m;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Google Apps SSO (with OpenID)";
        }
    }

    private static final Logger LOGGER = Logger.getLogger(OpenIdSsoSecurityRealm.class.getName());
}
//test1

