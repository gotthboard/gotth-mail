package plugin

import "fmt"

const (
	FirstWebmailName = "external-webmail"
	FirstDNSName     = "manual-dns-export"
	FirstCertName    = "manual-letsencrypt-cert"
	FirstBackupName  = "local-filesystem-backup"
	FirstNotifyName  = "telegram-notification-sink"
)

func FirstMechanismPlugins(serviceToken string) Registry {
	return Registry{Plugins: map[string]Registration{
		FirstWebmailName: {Name: FirstWebmailName, Seam: Webmail, Endpoint: "external-webmail-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"webmail.provider.config", "webmail.health"}},
		FirstDNSName:     {Name: FirstDNSName, Seam: DNS, Endpoint: "manual-dns-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"dns.export.zone", "dns.readiness.manual"}},
		FirstCertName:    {Name: FirstCertName, Seam: ACME, Endpoint: "cert-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"cert.manual.import", "cert.letsencrypt.request", "cert.expiry.check"}},
		FirstBackupName:  {Name: FirstBackupName, Seam: Backup, Endpoint: "backup-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"backup.local.write", "backup.local.verify", "backup.local.restore-preview"}},
		FirstNotifyName:  {Name: FirstNotifyName, Seam: Notification, Endpoint: "notification-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"notification.alert.sink", "notification.alert.send", "notification.prompt.send", "notification.delivery.status"}},
	}}
}

func FirstMechanismPlugin(name, serviceToken string) (Registration, error) {
	p, ok := FirstMechanismPlugins(serviceToken).Plugins[name]
	if !ok {
		return Registration{}, fmt.Errorf("unknown first mechanism plugin %q", name)
	}
	return p, nil
}
