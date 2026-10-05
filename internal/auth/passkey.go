package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Ключи входа (passkeys, WebAuthn): Windows Hello, Touch ID, Face ID. Приватная часть остаётся
// на устройстве, панель хранит только публичный ключ и счётчик подписей (SPEC FR-13.1).

// PasskeyUser — администратор глазами WebAuthn. Идентификатор — случайный handle, не имя входа:
// спецификация просит не класть в него персональные данные.
type PasskeyUser struct {
	Handle      []byte
	Login       string
	Display     string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte                         { return u.Handle }
func (u *PasskeyUser) WebAuthnName() string                       { return u.Login }
func (u *PasskeyUser) WebAuthnDisplayName() string                { return u.Display }
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// NewWebAuthn собирает проверяющего для конкретного имени панели. RPID — имя без схемы и порта;
// origin должен совпасть с тем, что видит браузер, иначе проверка отклонит подпись.
func NewWebAuthn(rpID, origin string) (*webauthn.WebAuthn, error) {
	if rpID == "" {
		return nil, fmt.Errorf("passkey: не задано имя панели (RPID)")
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "awgdash",
		RPOrigins:     []string{origin},
	})
}

// RegistrationOptions — как панель просит завести ключ: только встроенный аутентификатор
// (Hello, Touch ID, Face ID), обязательная проверка пользователя, ключ хранится на устройстве —
// иначе войти «по одной кнопке», не называя логина, не получится.
func RegistrationOptions(exclude []webauthn.Credential) []webauthn.RegistrationOption {
	return []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(exclude).CredentialDescriptors()),
	}
}

// LoginOptions — вход без имени: браузер сам предложит подходящий ключ.
func LoginOptions() []webauthn.LoginOption {
	return []webauthn.LoginOption{webauthn.WithUserVerification(protocol.VerificationRequired)}
}

// ToCredential разворачивает запись хранилища обратно в структуру библиотеки.
func ToCredential(p store.Passkey) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(p.CredentialID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("passkey %d: идентификатор не разобран: %w", p.ID, err)
	}
	c := webauthn.Credential{
		ID:              id,
		PublicKey:       p.PublicKey,
		AttestationType: p.Attestation,
		Authenticator:   webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
	c.Flags.BackupEligible, c.Flags.BackupState = p.BackupEligible, p.BackupState
	for _, t := range strings.Split(p.Transports, ",") {
		if t = strings.TrimSpace(t); t != "" {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
	}
	return c, nil
}

// FromCredential готовит запись хранилища по тому, что вернула проверка.
func FromCredential(adminID int64, c *webauthn.Credential, name string) store.Passkey {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return store.Passkey{
		AdminID:        adminID,
		CredentialID:   base64.RawURLEncoding.EncodeToString(c.ID),
		PublicKey:      c.PublicKey,
		AAGUID:         c.Authenticator.AAGUID,
		Transports:     strings.Join(transports, ","),
		Attestation:    c.AttestationType,
		SignCount:      c.Authenticator.SignCount,
		BackupEligible: c.Flags.BackupEligible,
		BackupState:    c.Flags.BackupState,
		Name:           name,
	}
}

// CredentialIDOf — идентификатор ключа в том виде, в каком он лежит в хранилище.
func CredentialIDOf(c *webauthn.Credential) string {
	return base64.RawURLEncoding.EncodeToString(c.ID)
}

// DecodeHandle разбирает user handle, пришедший от браузера.
func DecodeHandle(raw []byte) string { return string(raw) }
