package no.velthoven.lib.shiroyubikey;

import java.io.IOException;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Created by thomas on 06.12.15.
 */
public class OtpRealmInitTest {
    @BeforeClass
    static public void init() throws IOException {
        SecurityUtils.setSecurityManager(new DefaultSecurityManager(new OtpRealm()));
    }

    @Ignore
    @Test
    public void simpleTest() {
        Subject subject = SecurityUtils.getSubject();
        subject.login(new OtpToken() {

            String otp = "cccccceijfdgblfkiijrkeugugfhcitfhbgcjtbggvtk" +
                "";

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public String getOtp() {
                return otp;
            }
        });

        Assert.assertTrue("subject is not authenticated", subject.isAuthenticated());
        Assert.assertEquals("cccccceijfdg", subject.getPrincipal().toString());
        System.out.println(subject.getPrincipal().toString());


    }


}
