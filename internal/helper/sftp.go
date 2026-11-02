package helper

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/pkg/sftp"

	"github.com/nguyencongnamit/ssh-mcp/internal/pathpolicy"
)

// ServeSFTP runs a read-only SFTP server on rw (the SSH channel) that
// enforces the same path policy as the file tools. It replaces
// "internal-sftp -R" for agent-sftp so the sandbox mirror can only ever see
// allowed, non-denied files: denied paths do not exist from its point of view,
// whatever the sandbox later does with the bytes.
func (h *Helper) ServeSFTP(rw io.ReadWriteCloser) error {
	fs := &roFS{h: h}
	srv := sftp.NewRequestServer(rw, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs})
	err := srv.Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type roFS struct{ h *Helper }

// Fileread opens a file through secureOpen. pkg/sftp closes it.
func (f *roFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	file, _, err := f.h.secureOpen(r.Filepath, false)
	if err != nil {
		return nil, mapErr(err)
	}
	return file, nil
}

// Filewrite always refuses.
func (f *roFS) Filewrite(*sftp.Request) (io.WriterAt, error) {
	return nil, sftp.ErrSSHFxPermissionDenied
}

// Filecmd (setstat, rename, rmdir, mkdir, link, symlink, remove) always refuses.
func (f *roFS) Filecmd(*sftp.Request) error { return sftp.ErrSSHFxPermissionDenied }

// Filelist handles List, Stat and Readlink.
func (f *roFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		return f.list(r.Filepath)
	case "Stat":
		fi, err := f.stat(r.Filepath)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	case "Readlink":
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

// Lstat is answered like Stat: symlinks are never shown as links, only as
// the allowed thing they point to (or not at all).
func (f *roFS) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	fi, err := f.stat(r.Filepath)
	if err != nil {
		return nil, err
	}
	return listerAt{fi}, nil
}

// stat returns info for p only if both p and its resolved target are allowed.
// Anything else is reported as not existing.
func (f *roFS) stat(p string) (os.FileInfo, error) {
	c := pathpolicy.Clean(p)
	if c == "" {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	resolved, err := filepath.EvalSymlinks(c)
	if err != nil {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	if !f.h.allowed(c, fi.IsDir()) || !f.h.allowed(resolved, fi.IsDir()) {
		return nil, sftp.ErrSSHFxNoSuchFile
	}
	return renamed{fi, path.Base(c)}, nil
}

func (f *roFS) list(p string) (sftp.ListerAt, error) {
	dir, real, err := f.h.secureOpen(p, true)
	if err != nil {
		return nil, mapErr(err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, mapErr(err)
	}
	sort.Strings(names)
	var out listerAt
	for _, n := range names {
		fi, err := f.stat(path.Join(real, n))
		if err != nil {
			continue // denied, special, dangling or unreadable: invisible
		}
		out = append(out, fi)
	}
	return out, nil
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrDenied):
		return sftp.ErrSSHFxNoSuchFile
	case errors.Is(err, os.ErrPermission):
		return sftp.ErrSSHFxPermissionDenied
	}
	return sftp.ErrSSHFxNoSuchFile
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(dst []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[off:])
	if off+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// renamed reports a resolved target under the name the client asked for.
type renamed struct {
	os.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }
