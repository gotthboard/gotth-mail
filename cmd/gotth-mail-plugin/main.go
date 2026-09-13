package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := os.Getenv("GOTTH_MAIL_PLUGIN_NAME")
	if name == "" {
		return fmt.Errorf("GOTTH_MAIL_PLUGIN_NAME required")
	}
	token := os.Getenv("GOTTH_MAIL_PLUGIN_SERVICE_TOKEN")
	if token == "" {
		return fmt.Errorf("GOTTH_MAIL_PLUGIN_SERVICE_TOKEN required")
	}
	listen := os.Getenv("GOTTH_MAIL_PLUGIN_LISTEN")
	if listen == "" {
		listen = ":9443"
	}
	reg, err := plugin.FirstMechanismPlugin(name, token)
	if err != nil {
		return err
	}
	var sink plugin.NotificationSink
	if reg.Seam == plugin.Notification {
		sink, err = notificationSinkFor(reg.Name, os.Getenv)
		if err != nil {
			return err
		}
	}
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := grpc.NewServer()
	registry := plugin.Registry{Plugins: map[string]plugin.Registration{reg.Name: reg}}
	plugin.RegisterControlServer(srv, plugin.ControlServer{Name: reg.Name, Registry: registry})
	if reg.Seam == plugin.Notification {
		plugin.RegisterNotificationServer(srv, plugin.NotificationServer{Name: reg.Name, Registry: registry, Sink: sink})
	}
	return srv.Serve(lis)
}

func notificationSinkFor(name string, getenv func(string) string) (plugin.NotificationSink, error) {
	switch name {
	case plugin.FirstNotifyName:
		return plugin.LocalNotificationSink{}, nil
	case plugin.FirstEmailName:
		backend, err := notifyruntime.NewSignedEmailBackend(notifyruntime.EmailConfig{
			From:               getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_FROM"),
			To:                 getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_TO"),
			SigningFingerprint: getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT"),
			PrivateKeyFile:     getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE"),
			SMTPAddr:           getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_ADDR"),
		})
		if err != nil {
			return nil, fmt.Errorf("configure %s: %w", plugin.FirstEmailName, err)
		}
		return signedEmailNotificationSink{backend: backend}, nil
	default:
		return nil, fmt.Errorf("notification sink %q is not wired", name)
	}
}

type signedEmailNotificationSink struct {
	backend notifyruntime.SignedEmailBackend
}

func (s signedEmailNotificationSink) SendAlert(ctx context.Context, alert notification.Alert) (notification.DeliveryResult, error) {
	return s.backend.SendAlert(ctx, alert)
}

func (signedEmailNotificationSink) SendPrompt(context.Context, plugin.NotificationPrompt) (plugin.PromptResult, error) {
	return plugin.PromptResult{}, status.Error(codes.Unimplemented, "signed email notification sink does not support prompts")
}
