package main

import (
	"fmt"
	"net"
	"os"

	"forgejo/linus/gophermailforge/internal/plugin"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := os.Getenv("GMF_PLUGIN_NAME")
	if name == "" {
		return fmt.Errorf("GMF_PLUGIN_NAME required")
	}
	token := os.Getenv("GMF_PLUGIN_SERVICE_TOKEN")
	if token == "" {
		return fmt.Errorf("GMF_PLUGIN_SERVICE_TOKEN required")
	}
	listen := os.Getenv("GMF_PLUGIN_LISTEN")
	if listen == "" {
		listen = ":9443"
	}
	reg, err := plugin.FirstMechanismPlugin(name, token)
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := grpc.NewServer()
	registry := plugin.Registry{Plugins: map[string]plugin.Registration{reg.Name: reg}}
	plugin.RegisterControlServer(srv, plugin.ControlServer{Name: reg.Name, Registry: registry})
	if reg.Seam == plugin.Notification {
		plugin.RegisterNotificationServer(srv, plugin.NotificationServer{Name: reg.Name, Registry: registry})
	}
	return srv.Serve(lis)
}
