package plugin

import "fmt"

const (
	FirstWebmailName = "external-webmail"
	FirstDNSName     = "manual-dns-export"
	FirstCertName    = "manual-letsencrypt-cert"
	FirstBackupName  = "local-filesystem-backup"
	FirstNotifyName  = "telegram-notification-sink"
	FirstEmailName   = "signed-email-notification-sink"
)

func FirstMechanismPlugins(serviceToken string) Registry {
	registry, err := firstMechanismPlugins(serviceToken)
	if err != nil {
		panic("invalid built-in extension registration: " + err.Error())
	}
	return registry
}

func firstMechanismPlugins(serviceToken string) (Registry, error) {
	plugins := map[string]Registration{
		FirstWebmailName: {Name: FirstWebmailName, Seam: Webmail, Endpoint: "external-webmail-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"webmail.provider.config", "webmail.health"}},
		FirstDNSName:     {Name: FirstDNSName, Seam: DNS, Endpoint: "manual-dns-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"dns.export.zone", "dns.readiness.manual"}},
		FirstCertName:    {Name: FirstCertName, Seam: ACME, Endpoint: "cert-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"cert.manual.import", "cert.letsencrypt.request", "cert.expiry.check"}},
		FirstBackupName:  {Name: FirstBackupName, Seam: Backup, Endpoint: "backup-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"backup.local.write", "backup.local.verify", "backup.local.restore-preview"}},
		FirstNotifyName:  {Name: FirstNotifyName, Seam: Notification, Endpoint: "notification-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"notification.alert.sink", "notification.alert.send", "notification.prompt.send", "notification.delivery.status"}, SecretSlots: []string{"notification.telegram.bot-token"}},
	}
	for name, registration := range plugins {
		var err error
		registration.Foundation, err = NewFoundationBinding(registration)
		if err != nil {
			return Registry{}, fmt.Errorf("bind built-in extension %q: %w", name, err)
		}
		plugins[name] = registration
	}
	return Registry{Plugins: plugins}, nil
}

func FirstMechanismPlugin(name, serviceToken string) (Registration, error) {
	if name == FirstEmailName {
		registration := Registration{Name: FirstEmailName, Seam: Notification, Endpoint: "signed-email-notification-plugin:9443", Enabled: true, ServiceToken: serviceToken, Capabilities: []string{"notification.alert.sink", "notification.alert.send", "notification.alert.email.openpgp", "notification.delivery.status"}, SecretSlots: []string{"notification.email.private-key", "notification.email.smtp-password"}}
		var err error
		registration.Foundation, err = NewFoundationBinding(registration)
		return registration, err
	}
	registry, err := firstMechanismPlugins(serviceToken)
	if err != nil {
		return Registration{}, err
	}
	p, ok := registry.Plugins[name]
	if !ok {
		return Registration{}, fmt.Errorf("unknown first mechanism plugin %q", name)
	}
	if p.Foundation == nil {
		return Registration{}, fmt.Errorf("invalid extension foundation binding for %q", name)
	}
	return p, nil
}
