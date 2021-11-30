package com.example.ssltls;

import com.azure.security.keyvault.jca.KeyVaultLoadStoreParameter;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.hibernate.validator.internal.util.privilegedactions.NewInstance;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;


@RestController
@Controller
class SslController {

    @GetMapping(value = "/ssl-test")
    public String inbound(){
        return "Inbound TLS is working!";
    }

    @GetMapping(value = "/exit")
    public void exit() {
        System.exit(0);
    }

    @GetMapping (value = "/ssl-test-outbound")
    public String outbound() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException {
        KeyStore azureKeyVaultKeyStore = KeyStore.getInstance("AzureKeyVault");
        KeyVaultLoadStoreParameter keyVaultLoadStoreParameter = new KeyVaultLoadStoreParameter(
                System.getProperty("azure.keyvault.uri"));
        azureKeyVaultKeyStore.load(keyVaultLoadStoreParameter);
        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(azureKeyVaultKeyStore, null )
                .build();

        HostnameVerifier allowAll = (String hostName, SSLSession session) -> true;
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, allowAll);

        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(csf)
                .build();

        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory();

        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        String sslTest = "https://localhost:8443/ssl-test";

        ResponseEntity<String> response = restTemplate.getForEntity(sslTest, String.class);

        return "Outbound TLS" +
                (response.getStatusCode() == HttpStatus.OK ? "is" : "is not") + "Working!";
    }
}
