//go:build windows

package safeio

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no O_NOFOLLOW; reparse points are rejected by the regular-file
// check on the opened handle where the platform reports them.
const (
	readFlags   = os.O_RDONLY
	dirFlags    = os.O_RDONLY
	appendFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	tmpFlags    = os.O_WRONLY | os.O_CREATE | os.O_EXCL
)

func isSymlinkLoop(error) bool { return false }

func syncDir(*os.File) error { return nil }

// writeMask is every access right that lets a principal change the file or
// its security: write data, append, write attributes and EA, delete, and
// change the DACL or the owner, plus the generic write and all rights.
const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

const (
	aceInheritOnly = 0x08 // INHERIT_ONLY_ACE: not an access grant on this object
	accessAllowed  = 0    // ACCESS_ALLOWED_ACE_TYPE
)

// checkOwnerPerm validates the owner and the DACL of an open file.
//
// Owner (RequireOwner): the file must be owned by the process's own user,
// by its token's default owner (an elevated administrator creates objects
// owned by BUILTIN\Administrators), or by BUILTIN\Administrators when the
// process runs as LocalSystem. Anything else is ErrOwner.
//
// Permissions (MaxPerm != 0): no access-allowed entry may grant a write
// right to a principal other than the owner, the process's user and
// default owner, LocalSystem and BUILTIN\Administrators; a missing DACL
// (everyone has full access) fails too. Unix mode bits mean nothing here,
// so MaxPerm only asks for "private to us".
func checkOwnerPerm(f *os.File, _ os.FileInfo, o Opts) error {
	if !o.RequireOwner && o.MaxPerm == 0 {
		return nil
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: cannot read security descriptor: %v", ErrOwner, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return ErrOwner
	}
	trusted, err := trustedSIDs()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOwner, err)
	}
	if o.RequireOwner && !trusted.ownerOK(owner) {
		return ErrOwner
	}
	if o.MaxPerm == 0 {
		return nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ErrPerm // no DACL: everyone has full access
	}
	return daclPrivate(dacl, owner, trusted)
}

type sidSet struct {
	user, tokenOwner, system, admins *windows.SID
}

func trustedSIDs() (sidSet, error) {
	var s sidSet
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return s, err
	}
	s.user = u.User.Sid
	if n, err := tokenOwnerSID(tok); err == nil {
		s.tokenOwner = n
	}
	if s.system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		return s, err
	}
	if s.admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		return s, err
	}
	return s, nil
}

// tokenOwnerInfo is TOKEN_OWNER, which x/sys/windows does not define.
type tokenOwnerInfo struct{ Owner *windows.SID }

func tokenOwnerSID(tok windows.Token) (*windows.SID, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenOwner, nil, 0, &n)
	if n == 0 {
		return nil, fmt.Errorf("token owner size")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenOwner, &buf[0], n, &n); err != nil {
		return nil, err
	}
	return (*tokenOwnerInfo)(unsafe.Pointer(&buf[0])).Owner.Copy()
}

func (s sidSet) ownerOK(owner *windows.SID) bool {
	if owner.Equals(s.user) || (s.tokenOwner != nil && owner.Equals(s.tokenOwner)) {
		return true
	}
	return owner.Equals(s.admins) && s.user.Equals(s.system)
}

// principalOK is who may hold write access besides the owner.
func (s sidSet) principalOK(sid, owner *windows.SID) bool {
	return sid.Equals(owner) || sid.Equals(s.user) || sid.Equals(s.system) || sid.Equals(s.admins) ||
		(s.tokenOwner != nil && sid.Equals(s.tokenOwner))
}

// daclPrivate fails when any grant of a write right goes to someone else.
func daclPrivate(acl *windows.ACL, owner *windows.SID, t sidSet) error {
	// ACL.AceCount is not exported by x/sys; read it from the header.
	count := int(*(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(acl)) + 4)))
	for i := 0; i < count; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return ErrPerm
		}
		if ace.Header.AceType != accessAllowed || ace.Header.AceFlags&aceInheritOnly != 0 {
			continue // deny entries and inherit-only entries grant nothing here
		}
		if ace.Mask&writeMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !t.principalOK(sid, owner) {
			return ErrPerm
		}
	}
	return nil
}
