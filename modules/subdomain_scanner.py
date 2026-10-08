import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SubdomainResult:
    subdomain: str
    ip: str
    status: str
    response_time: float


class SubdomainScanner:
    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp",
        "pop", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "gateway", "vpn", "remote",
        "admin", "test", "dev", "staging", "api", "app",
        "blog", "shop", "store", "portal", "support",
        "help", "docs", "wiki", "forum", "community",
        "git", "gitlab", "github", "bitbucket", "jenkins",
        "ci", "cd", "docker", "k8s", "kubernetes",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "elasticsearch", "kibana", "grafana", "prometheus",
        "cdn", "static", "assets", "media", "images", "img",
        "cdn1", "cdn2", "edge", "cloud", "aws", "azure", "gcp",
        "s3", "blob", "storage", "backup", "bak",
        "old", "new", "legacy", "archive",
        "beta", "alpha", "demo", "sandbox", "lab",
        "internal", "intranet", "extranet",
        "monitor", "status", "health", "healthcheck",
        "login", "auth", "sso", "oauth", "ldap",
        "crm", "erp", "hr", "finance", "accounting",
        "reports", "analytics", "dashboard", "panel",
        "calendar", "meet", "video", "conference",
        "intranet", "portal", "sharepoint", "office",
        "exchange", "owa", "autodiscover",
        "skype", "teams", "slack", "discord",
        "jira", "confluence", "trello", "asana",
        "git", "svn", "cvs", "hg",
        "proxy", "squid", "nginx", "apache", "httpd",
        "tomcat", "jboss", "weblogic", "wildfly",
        "php", "python", "node", "ruby", "java",
        "iis", "lighttpd", "caddy", "traefik",
        "kafka", "rabbitmq", "activemq", "zeromq",
        "consul", "etcd", "zookeeper", "nacos",
        "vault", "secrets", "cert", "ssl", "tls",
        "acme", "letsencrypt", "certbot",
        "im", "chat", "irc", "xmpp",
        "sms", "mms", "notify", "notification",
        "push", "webhook", "webhooks",
        "search", "solr", "elastic", "meilisearch",
        "analytics", "tracking", "pixel", "tag",
        "ads", "ad", "adserver", "adsense",
        "payment", "pay", "checkout", "cart", "billing",
        "invoice", "order", "orders", "purchase",
        "affiliate", "partners", "reseller",
        "download", "downloads", "dl",
        "upload", "uploads", "ul",
        "files", "file", "fs", "smb", "nfs", "cifs",
        "backup", "backups", "bak", "snap", "snapshot",
        "log", "logs", "logging", "syslog",
        "ntp", "time", "clock",
        "snmp", "nagios", "zabbix", "icinga",
        "cacti", "mrtg", "rrd", "graphite",
        "ansible", "puppet", "chef", "salt",
        "terraform", "packer", "vagrant",
        "ci", "cd", "drone", "circle", "travis",
        "sonar", "sonarqube', 'nexus", "artifactory",
        "registry", "registry2", "harbor",
        "etcd", "consul", "vault",
        "kafka", "zk", "zookeeper",
        "es", "elastic", "kibana", "logstash",
        "grafana", "prometheus", "alertmanager",
        "thanos", "loki", "mimir",
        "minio", "s3", "ceph", "swift",
        "gluster", "nfs", "cifs", "smb",
        "ldap", "ad", "kerberos", "radius",
        "tacacs", "freeradius",
        "dns", "bind", "named", "unbound", "pihole",
        "dhcp", "isc-dhcp", "kea",
        "proxy", "nginx", "haproxy", "traefik", "caddy",
        "varnish", "squid", "privoxy",
        "mail", "postfix", "sendmail", "exim", "dovecot",
        "roundcube", "sovermin", "zimbra",
        "git", "gitea", "gogs", "gitlab", "bitbucket",
        "jenkins", "drone", "buildkite",
        "sonarqube", "nexus", "artifactory",
        "harbor", "registry", "distribution",
        "portainer", "swarmpit", "rancher",
        "kubernetes", "k8s", "k3s", "k0s", "rke",
        "etcd", "apiserver", "scheduler", "controller",
        "ingress", "nginx-ingress", "traefik-ingress",
        "cert-manager", "certbot", "acme",
        "vault", "consul", "nomad",
        "packer", "terraform", "waypoint",
        "vagrant", "virtualbox", "vmware",
        "proxmox", "esxi", "xen",
        "openstack", "cloudstack", "eucalyptus",
        "aws", "azure", "gcp", "do", "linode",
        "cloudflare", "cloudfront", "fastly",
        "akamai", "limelight", "keycdn",
        "sentry", "bugsnag", "rollbar",
        "datadog", "newrelic", "appdynamics",
        "splunk", "sumologic", "loggly",
        "papertrail", "logentries", "logz.io",
        "pagerduty", "opsgenie", "victorops",
        "jira", "confluence", "trello", "asana",
        "slack", "discord", "mattermost", "rocketchat",
        "teams", "zoom", "meet", "webex",
        "mattermost", "rocket.chat", "zulip",
        "nextcloud", "owncloud", "seafile",
        "dropbox", "gdrive", "onedrive",
        "matrix", "element", "synapse",
        "mastodon", "pleroma", "misskey",
        "wordpress", "drupal", "joomla", "ghost",
        "magento", "prestashop", "opencart",
        "mediawiki", "dokuwiki", "tiddlywiki",
        "moodle", "canvas", "blackboard",
        "openedx", "edx", "coursera",
    ]

    def __init__(self, domain: str, wordlist: Optional[list[str]] = None,
                 threads: int = 50, timeout: float = 3.0):
        self.domain = domain
        self.wordlist = wordlist or self.DEFAULT_WORDLIST
        self.threads = threads
        self.timeout = timeout
        self.results: list[SubdomainResult] = []

    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore) -> Optional[SubdomainResult]:
        import aiohttp
        full_domain = f"{subdomain}.{self.domain}"

        async with semaphore:
            start = time.time()
            try:
                import socket
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(
                    None,
                    lambda: socket.gethostbyname(full_domain),
                )
                response_time = (time.time() - start) * 1000

                return SubdomainResult(
                    subdomain=full_domain,
                    ip=ip,
                    status="FOUND",
                    response_time=round(response_time, 2),
                )
            except (socket.gaierror, OSError):
                return None

    async def scan(self) -> list[SubdomainResult]:
        semaphore = asyncio.Semaphore(self.threads)
        tasks = [self._check_subdomain(sub, semaphore) for sub in self.wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        self.results = [r for r in results if isinstance(r, SubdomainResult)]
        self.results.sort(key=lambda x: x.subdomain)
        return self.results

    def scan_sync(self) -> list[SubdomainResult]:
        return asyncio.run(self.scan())

    def get_summary(self) -> dict:
        return {
            "domain": self.domain,
            "total_checked": len(self.wordlist),
            "found": len(self.results),
            "results": [
                {
                    "subdomain": r.subdomain,
                    "ip": r.ip,
                    "status": r.status,
                    "response_time_ms": r.response_time,
                }
                for r in self.results
            ],
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.get_summary(), indent=2)


if __name__ == "__main__":
    scanner = SubdomainScanner("example.com", threads=20)
    results = scanner.scan_sync()
    print(f"\nFound {len(results)} subdomains for example.com")
    for r in results:
        print(f"  {r.subdomain} -> {r.ip} ({r.response_time}ms)")
