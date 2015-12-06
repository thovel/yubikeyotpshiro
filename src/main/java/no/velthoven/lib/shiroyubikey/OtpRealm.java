package no.velthoven.lib.shiroyubikey;

import java.io.IOException;
import java.io.InputStream;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.SimplePrincipalCollection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.yubico.client.v2.VerificationResponse;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import com.yubico.client.v2.exceptions.YubicoVerificationException;

/**
 * Created by thomas on 06.12.15.
 */
public class OtpRealm implements Realm {

    private final String realmName;
    YubicoClient client;


    public OtpRealm() throws IOException {
        this.realmName = this.getClass().getSimpleName();
        initYubuciClient();
    }
    public OtpRealm(String name) throws IOException {
        this.realmName = name;
        initYubuciClient();
    }

    private void initYubuciClient() throws IOException {
        JsonNode dir = ensureClientSettings();
        int clientId = ensureInt(dir, "clientId");
        String apiKey = ensureString(dir, "apiKey");

        client = YubicoClient.getClient(clientId, apiKey);

    }


    @Override
    public String getName() {
        return realmName;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof OtpToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (!(token instanceof OtpToken)) {
            return null;
        }

        OtpToken otpToken = (OtpToken) token;

        VerificationResponse response;
        try {
            response = client.verify(otpToken.getOtp());
        } catch (YubicoVerificationException e) {
            throw new AuthenticationException(e);
        } catch (YubicoValidationFailure yubicoValidationFailure) {
            throw new AuthenticationException(yubicoValidationFailure);
        }

        if (!response.isOk()) {
            throw new AuthenticationException("verification failed ("+ response.getStatus().name() +")");
        }

        SimplePrincipalCollection principals = new SimplePrincipalCollection();

        String key = response.getPublicId();
        principals.add(key, realmName);
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo();
        info.setPrincipals(principals);
        return info;
    }

    private int ensureInt(JsonNode parent, String childName) {
        Preconditions.checkNotNull(parent, "must have a value");
        JsonNode childNode = parent.get(childName);
        Preconditions.checkNotNull(childNode, "must contain " + childName);
        return childNode.asInt();
    }
    private String ensureString(JsonNode parent, String childName) {
        Preconditions.checkNotNull(parent, "must have a value");
        JsonNode childNode = parent.get(childName);
        Preconditions.checkNotNull(childNode, "must contain " + childName);
        return childNode.asText();
    }


    protected JsonNode ensureClientSettings() throws IOException {
        InputStream in = this.getClass().getClassLoader()
            .getResourceAsStream("yubiClientSettings.yaml");
        YAMLFactory factory = new YAMLFactory();
        ObjectMapper mapper = new ObjectMapper(factory);
        return mapper.readTree(in);
    }


}
