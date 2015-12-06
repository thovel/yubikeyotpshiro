package no.velthoven.lib.shiroyubikey;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * Created by thomas on 06.12.15.
 */
public interface OtpToken extends AuthenticationToken {
    String getOtp();
}
