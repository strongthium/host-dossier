namespace Strongthium.HostDossier;

/// <summary>
/// The big services by their AS numbers and host names, so that a report can say "Google Workspace" rather than
/// only <c>aspmx.l.google.com</c>. Only a label on top of what was looked up: anything not here shows its network's
/// own name.
/// </summary>
public static class KnownServices
{
    private static readonly Dictionary<long, (string Name, ServiceKind Kind)> Networks = new()
    {
        [13335] = ("Cloudflare", ServiceKind.Cdn), [209242] = ("Cloudflare", ServiceKind.Cdn),
        [54113] = ("Fastly", ServiceKind.Cdn), [20940] = ("Akamai", ServiceKind.Cdn), [16625] = ("Akamai", ServiceKind.Cdn), [21342] = ("Akamai", ServiceKind.Cdn),
        [15133] = ("Edgio (Edgecast)", ServiceKind.Cdn), [22822] = ("Edgio (Limelight)", ServiceKind.Cdn), [60068] = ("CDN77 (Datacamp)", ServiceKind.Cdn),
        [19551] = ("Imperva Incapsula", ServiceKind.Security), [30148] = ("Sucuri", ServiceKind.Security), [55002] = ("Defense.net (F5)", ServiceKind.Security),
        [16509] = ("Amazon Web Services", ServiceKind.Cloud), [14618] = ("Amazon Web Services", ServiceKind.Cloud), [8987] = ("Amazon Web Services", ServiceKind.Cloud),
        [15169] = ("Google", ServiceKind.Cloud), [396982] = ("Google Cloud", ServiceKind.Cloud), [19527] = ("Google", ServiceKind.Cloud), [36492] = ("Google", ServiceKind.Cloud),
        [8075] = ("Microsoft", ServiceKind.Cloud), [8068] = ("Microsoft", ServiceKind.Cloud), [8069] = ("Microsoft", ServiceKind.Cloud),
        [31898] = ("Oracle Cloud", ServiceKind.Cloud), [36351] = ("IBM Cloud (SoftLayer)", ServiceKind.Cloud), [45102] = ("Alibaba Cloud", ServiceKind.Cloud),
        [132203] = ("Tencent Cloud", ServiceKind.Cloud), [14061] = ("DigitalOcean", ServiceKind.Cloud), [20473] = ("Vultr", ServiceKind.Cloud), [63949] = ("Linode (Akamai)", ServiceKind.Cloud),
        [16276] = ("OVHcloud", ServiceKind.Hosting), [24940] = ("Hetzner", ServiceKind.Hosting), [213230] = ("Hetzner Cloud", ServiceKind.Hosting), [212317] = ("Hetzner Cloud", ServiceKind.Hosting),
        [51167] = ("Contabo", ServiceKind.Hosting), [12876] = ("Scaleway", ServiceKind.Hosting), [60781] = ("Leaseweb", ServiceKind.Hosting), [28753] = ("Leaseweb", ServiceKind.Hosting),
        [8560] = ("IONOS", ServiceKind.Hosting), [26496] = ("GoDaddy", ServiceKind.Hosting), [398101] = ("GoDaddy", ServiceKind.Hosting), [46606] = ("Unified Layer (Bluehost)", ServiceKind.Hosting),
        [19871] = ("Network Solutions", ServiceKind.Hosting), [22612] = ("Namecheap", ServiceKind.Hosting), [40034] = ("Confluence Networks", ServiceKind.Hosting), [32244] = ("Liquid Web", ServiceKind.Hosting),
        [29802] = ("HIVELOCITY", ServiceKind.Hosting), [62567] = ("DigitalOcean", ServiceKind.Cloud), [19318] = ("Interserver", ServiceKind.Hosting), [53667] = ("FranTech (BuyVM)", ServiceKind.Hosting),
        [47583] = ("Hostinger", ServiceKind.Hosting), [34619] = ("Cizgi Telekom", ServiceKind.Hosting), [63410] = ("PrivateSystems", ServiceKind.Hosting), [29854] = ("WestHost", ServiceKind.Hosting),
        [32934] = ("Meta (Facebook)", ServiceKind.Cloud), [54115] = ("Meta (Facebook)", ServiceKind.Cloud), [714] = ("Apple", ServiceKind.Cloud), [6185] = ("Apple", ServiceKind.Cloud),
        [36459] = ("GitHub", ServiceKind.Cloud), [14413] = ("LinkedIn", ServiceKind.Cloud), [13414] = ("X (Twitter)", ServiceKind.Cloud), [40027] = ("Netlify", ServiceKind.Cloud), [60626] = ("Vercel", ServiceKind.Cloud),
        [26211] = ("Proofpoint", ServiceKind.Mail), [22843] = ("Proofpoint", ServiceKind.Mail), [30031] = ("Mimecast", ServiceKind.Mail), [15830] = ("Equinix", ServiceKind.Hosting),
        [395747] = ("Twilio SendGrid", ServiceKind.Mail), [11377] = ("Twilio SendGrid", ServiceKind.Mail), [29789] = ("Mailchimp", ServiceKind.Mail), [62013] = ("Mailchimp", ServiceKind.Mail), [394695] = ("Mailgun", ServiceKind.Mail),
        [14340] = ("Salesforce", ServiceKind.Cloud), [1999] = ("Salesforce", ServiceKind.Cloud), [395082] = ("Fastmail", ServiceKind.Mail), [62371] = ("Proton", ServiceKind.Mail),
    };

    private static readonly (string Suffix, string Name)[] MailHosts =
    [
        (".mail.protection.outlook.com", "Microsoft 365"), (".mx.microsoft", "Microsoft 365"), (".olc.protection.outlook.com", "Outlook.com"),
        ("aspmx.l.google.com", "Google Workspace"), (".aspmx.l.google.com", "Google Workspace"), ("smtp.google.com", "Google Workspace"), (".googlemail.com", "Google Workspace"), (".google.com", "Google"),
        (".pphosted.com", "Proofpoint"), (".ppe-hosted.com", "Proofpoint Essentials"), (".mimecast.com", "Mimecast"), (".mimecast.co.za", "Mimecast"),
        (".barracudanetworks.com", "Barracuda"), (".iphmx.com", "Cisco Secure Email"), (".messagelabs.com", "Broadcom Email Security"), (".trendmicro.com", "Trend Micro"), (".sophos.com", "Sophos"), (".fireeyecloud.com", "Trellix"), (".forcepoint.com", "Forcepoint"), (".antispamcloud.com", "SpamExperts"), (".mailcontrol.com", "Forcepoint"),
        (".zoho.com", "Zoho Mail"), (".zoho.eu", "Zoho Mail"), (".zoho.in", "Zoho Mail"), (".messagingengine.com", "Fastmail"), (".protonmail.ch", "Proton Mail"),
        ("mx.cloudflare.net", "Cloudflare Email Routing"), (".mx.cloudflare.net", "Cloudflare Email Routing"), (".amazonses.com", "Amazon SES"), (".amazonaws.com", "Amazon SES"), (".awsapps.com", "Amazon WorkMail"),
        (".mailgun.org", "Mailgun"), (".sendgrid.net", "Twilio SendGrid"), (".postmarkapp.com", "Postmark"), (".icloud.com", "iCloud Mail"), (".yandex.net", "Yandex Mail"), (".yandex.ru", "Yandex Mail"), (".mail.ru", "Mail.ru"),
        (".secureserver.net", "GoDaddy"), (".registrar-servers.com", "Namecheap"), (".privateemail.com", "Namecheap Private Email"), (".ovh.net", "OVHcloud"), (".ionos.com", "IONOS"), (".kundenserver.de", "IONOS"), (".hostinger.com", "Hostinger"), (".emailsrvr.com", "Rackspace"), (".migadu.com", "Migadu"), (".mxroute.com", "MXroute"), (".improvmx.com", "ImprovMX"), (".forwardemail.net", "Forward Email"),
    ];

    private static readonly (string Suffix, string Name)[] DnsHosts =
    [
        (".ns.cloudflare.com", "Cloudflare"), (".awsdns-", "Amazon Route 53"), (".azure-dns.", "Azure DNS"), (".googledomains.com", "Google Domains"), (".google.com", "Google"), (".domaincontrol.com", "GoDaddy"),
        (".nsone.net", "NS1"), (".ultradns.", "UltraDNS"), (".dnsmadeeasy.com", "DNS Made Easy"), (".registrar-servers.com", "Namecheap"), (".akam.net", "Akamai"), (".dynect.net", "Dyn (Oracle)"), (".ovh.net", "OVHcloud"),
        (".hetzner.com", "Hetzner"), (".hetzner.de", "Hetzner"), (".digitalocean.com", "DigitalOcean"), (".linode.com", "Linode"), (".vultr.com", "Vultr"), (".wixdns.net", "Wix"), (".squarespacedns.com", "Squarespace"),
        (".hover.com", "Hover"), (".gandi.net", "Gandi"), (".dnsimple.com", "DNSimple"), (".name-services.com", "Enom"), (".worldnic.com", "Network Solutions"), (".bluehost.com", "Bluehost"), (".hostgator.com", "HostGator"), (".dns.he.net", "Hurricane Electric"), (".he.net", "Hurricane Electric"), (".vercel-dns.com", "Vercel"), (".netlify.com", "Netlify"), (".nsdns", "Neustar"),
    ];

    private static readonly (string Include, string Name)[] SendingServices =
    [
        ("_spf.google.com", "Google Workspace"), ("spf.protection.outlook.com", "Microsoft 365"), ("sendgrid.net", "Twilio SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
        ("servers.mcsv.net", "Mailchimp"), ("mandrillapp.com", "Mandrill"), ("spf.mandrillapp.com", "Mandrill"), ("mail.zendesk.com", "Zendesk"), ("_spf.salesforce.com", "Salesforce"), ("hubspotemail.net", "HubSpot"), ("spf.mtasv.net", "Postmark"), ("zoho.com", "Zoho Mail"), ("zoho.eu", "Zoho Mail"), ("spf.messagingengine.com", "Fastmail"), ("_spf.protonmail.ch", "Proton Mail"),
        ("_spf.mx.cloudflare.net", "Cloudflare Email Routing"), ("pphosted.com", "Proofpoint"), ("spf.mimecast.org", "Mimecast"), ("_netblocks.mimecast.com", "Mimecast"), ("mktomail.com", "Marketo"), ("spf.freshdesk.com", "Freshdesk"), ("email.freshdesk.com", "Freshdesk"), ("secureserver.net", "GoDaddy"), ("spf.sendinblue.com", "Brevo"), ("spf.brevo.com", "Brevo"), ("_spf.elasticemail.com", "Elastic Email"), ("spf.privateemail.com", "Namecheap Private Email"), ("icloud.com", "iCloud Mail"), ("sparkpostmail.com", "SparkPost"), ("spf.smtp2go.com", "SMTP2GO"),
    ];

    private static readonly (string Selector, string Name)[] DkimSelectors =
    [
        ("google", "Google Workspace"), ("selector1", "Microsoft 365"), ("selector2", "Microsoft 365"), ("k1", "Mailchimp"), ("k2", "Mailchimp"), ("k3", "Mailchimp"), ("s1", "SendGrid, or another"), ("s2", "SendGrid, or another"),
        ("smtpapi", "Twilio SendGrid"), ("mandrill", "Mandrill"), ("mailgun", "Mailgun"), ("mg", "Mailgun"), ("pm", "Postmark"), ("fm1", "Fastmail"), ("fm2", "Fastmail"), ("fm3", "Fastmail"), ("protonmail", "Proton Mail"), ("protonmail2", "Proton Mail"), ("protonmail3", "Proton Mail"), ("zoho", "Zoho Mail"), ("zmail", "Zoho Mail"), ("amazonses", "Amazon SES"), ("sig1", "iCloud Mail"), ("hs1", "HubSpot"), ("hs2", "HubSpot"), ("zendesk1", "Zendesk"), ("zendesk2", "Zendesk"), ("cf2024-1", "Cloudflare Email Routing"),
    ];

    public static (string Name, ServiceKind Kind)? ForNetwork(long asn) => Networks.TryGetValue(asn, out var service) ? service : null;

    public static string? ForMailHost(string host) => BySuffix(MailHosts, host);

    public static string? ForNameServer(string host) => host.Contains(".awsdns-", StringComparison.Ordinal) ? "Amazon Route 53" : BySuffix(DnsHosts, host);

    public static string? ForSpfInclude(string domain)
    {
        foreach (var (include, name) in SendingServices)
        {
            if (domain == include || domain.EndsWith("." + include, StringComparison.Ordinal)) return name;
        }
        return null;
    }

    public static string? ForDkimSelector(string selector) =>
        Array.Find(DkimSelectors, s => s.Selector == selector) is { Name: not null } found ? found.Name : null;

    private static string? BySuffix((string Suffix, string Name)[] table, string host)
    {
        foreach (var (suffix, name) in table)
        {
            if (suffix.StartsWith('.') ? host.EndsWith(suffix, StringComparison.Ordinal) || host.Contains(suffix + ".", StringComparison.Ordinal) : host == suffix) return name;
        }
        return null;
    }
}
