package credentials

import (
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
)

type CredentialFile struct {
	FilePath string      `yaml:"path"`
	Mode     os.FileMode `yaml:"mode"`
	Owner    string      `yaml:"owner"`
	Group    string      `yaml:"group"`
	owner    *user.User
	group    *user.Group
}

func NewCredentialFile(path string, mode os.FileMode, owner string, group string) (*CredentialFile, error) {
	f := &CredentialFile{}
	f.FilePath = path
	f.Mode = mode
	f.Owner = owner
	f.Group = group

	err := f.populateUserGroupData()
	return f, err
}

func (f *CredentialFile) populateUserGroupData() error {
	var o *user.User
	var g *user.Group
	var err error
	if f.Owner != "" {
		o, err = user.Lookup(f.Owner)
	} else {
		o, err = user.Current()
	}
	if err != nil {
		return err
	}
	f.Owner = o.Name
	f.owner = o

	if f.Group != "" {
		g, err = user.LookupGroup(f.Group)
	} else {
		g, err = user.LookupGroupId(f.owner.Gid)
	}
	if err != nil {
		return err
	}
	f.Group = g.Name
	f.group = g
	return nil
}

func (f *CredentialFile) Write(content string) error {
	if err := ioutil.WriteFile(f.FilePath, []byte(content), f.Mode); err != nil {
		return err
	}

	if f.owner == nil || f.group == nil {
		err := f.populateUserGroupData()
		if err != nil {
			return err
		}
	}

	uid, err := strconv.Atoi(f.owner.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(f.group.Gid)
	if err != nil {
		return err
	}

	if err := os.Chown(f.FilePath, uid, gid); err != nil {
		return err
	}
	return nil
}

func (f *CredentialFile) Read() (string, error) {
	contents, err := ioutil.ReadFile(f.Path())
	return string(contents), err
}

func (f *CredentialFile) Path() string {
	return f.FilePath
}
