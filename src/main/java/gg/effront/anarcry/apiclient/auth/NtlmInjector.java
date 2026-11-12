package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class NtlmInjector implements AuthInjector {

    @Override
    public String mode() {
        return "ntlm";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.Ntlm ntlm)) {
            return request;
        }
        String domain = ntlm.domain() != null ? ntlm.domain() : "";
        String user = ntlm.username() != null ? ntlm.username() : "";
        byte[] type1 = buildType1Message(domain);
        String negotiate = "NTLM " + Base64.getEncoder().encodeToString(type1);
        return AuthInjectorRegistry.addHeader(request, "Authorization", negotiate);
    }

    private byte[] buildType1Message(String domain) {
        byte[] domainBytes = domain.toUpperCase().getBytes(StandardCharsets.US_ASCII);
        byte[] msg = new byte[32 + domainBytes.length];
        System.arraycopy("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII), 0, msg, 0, 8);
        msg[8] = 1;
        int flags = 0x00008206;
        msg[12] = (byte) (flags & 0xff);
        msg[13] = (byte) ((flags >> 8) & 0xff);
        msg[14] = (byte) ((flags >> 16) & 0xff);
        msg[15] = (byte) ((flags >> 24) & 0xff);
        msg[16] = (byte) (domainBytes.length & 0xff);
        msg[17] = (byte) ((domainBytes.length >> 8) & 0xff);
        msg[18] = msg[16];
        msg[19] = msg[17];
        msg[20] = 32;
        System.arraycopy(domainBytes, 0, msg, 32, domainBytes.length);
        return msg;
    }
}
