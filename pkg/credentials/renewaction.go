package credentials

import (
	systemctl "github.com/coreos/go-systemd/dbus"
)

type ReloadOrRestartSystemdUnit struct {
	UnitName string
}

func (a *ReloadOrRestartSystemdUnit) Do() error {
	c, err := systemctl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.ReloadOrRestartUnit(a.UnitName, "", nil)
	return err
}
