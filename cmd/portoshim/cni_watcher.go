package main

import (
	"fmt"
	"os"
	"path/filepath"

	cni "github.com/containerd/go-cni"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// cniWatcher watches filesystem events in CNI config directory to reload.
type cniWatcher struct {
	fs     *fsnotify.Watcher
	plugin cni.CNI

	confDir string
	log     *zap.Logger
}

func netPluginOptions() []cni.Opt {
	return []cni.Opt{
		cni.WithLoNetwork,
		cni.WithDefaultConf,
	}
}

func newCNIWatcher(log *zap.Logger) (*cniWatcher, error) {
	confDir := Cfg.CNI.ConfDir

	plugin, err := cni.New(cni.WithMinNetworkCount(networkAttachCount),
		cni.WithPluginConfDir(confDir),
		cni.WithPluginDir([]string{Cfg.CNI.BinDir}),
		cni.WithInterfacePrefix(ifPrefixName))
	if err != nil {
		return nil, fmt.Errorf("initialize cni: %w", err)
	}

	if err := plugin.Load(netPluginOptions()...); err != nil {
		log.Warn("CNI plugin load failed", zap.Error(err))
	}

	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	// /etc/cni has to be readable for non-root users (0755), because /etc/cni/tuning/allowlist.conf is used for rootless mode too.
	// This file was introduced in CNI plugins 1.2.0 (https://github.com/containernetworking/plugins/pull/693), and its path is hard-coded.
	confDirParent := filepath.Dir(confDir)
	if err := os.MkdirAll(confDirParent, 0o755); err != nil {
		return nil, fmt.Errorf("create the parent of the CNI config dir %q: %w", confDirParent, err)
	}

	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return nil, fmt.Errorf("create CNI config dir %q for watch: %w", confDir, err)
	}

	if err := fs.Add(confDir); err != nil {
		return nil, fmt.Errorf("watch CNI config dir %q: %w", confDir, err)
	}

	return &cniWatcher{
		fs:      fs,
		confDir: confDir,
		plugin:  plugin,
		log:     log,
	}, nil
}

func (w *cniWatcher) Plugin() cni.CNI {
	return w.plugin
}

func (w *cniWatcher) Run() error {
	w.log.Info("Starting CNI config watcher", zap.String("dir", w.confDir))
watchLoop:
	for {
		select {
		case event, ok := <-w.fs.Events:
			if !ok {
				break watchLoop
			}
			w.log.Debug("Received event from CNI config dir", zap.Stringer("event", event))

			// Only reload config when receiving write/rename/remove
			// events
			if event.Has(fsnotify.Chmod) || event.Has(fsnotify.Create) {
				continue
			}

			if err := w.plugin.Load(netPluginOptions()...); err != nil {
				w.log.Warn("Reload CNI configuration", zap.Error(err))
			}
		case err := <-w.fs.Errors:
			if err != nil {
				w.log.Error("Watch CNI config dir", zap.Error(err))
				return err
			}
		}
	}
	w.log.Info("Stopping CNI config watcher")
	return nil
}

func (w *cniWatcher) Close() error {
	return w.fs.Close()
}
