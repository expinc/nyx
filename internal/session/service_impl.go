package session

import (
	"errors"
	"os"
	"time"

	"nyx/internal/common"
)

type service struct {
	cfg   Config
	nowFn func() time.Time
}

func (s *service) CreateCLISession(repoName string) (CreateSessionResult, error) {
	if err := s.validateRepoName(repoName); err != nil {
		return CreateSessionResult{}, err
	}
	if err := s.ensureReady(); err != nil {
		return CreateSessionResult{}, err
	}

	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return CreateSessionResult{}, err
	}
	s.purgeSessionArtifacts(repoName, repoNameHash)

	path, err := cliSessionPath(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return CreateSessionResult{}, err
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return CreateSessionResult{}, err
	}

	now := s.nowUTC()
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      ModeCLI,
		RepoName:  repoName,
		SessionID: sessionID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := writeSessionRecord(path, rec); err != nil {
		return CreateSessionResult{}, err
	}

	return CreateSessionResult{
		Mode:      ModeCLI,
		RepoName:  rec.RepoName,
		SessionID: rec.SessionID,
		CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

func (s *service) CreateHTTPSession(repoName string) (CreateSessionResult, error) {
	if err := s.validateRepoName(repoName); err != nil {
		return CreateSessionResult{}, err
	}
	if err := s.ensureReady(); err != nil {
		return CreateSessionResult{}, err
	}

	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return CreateSessionResult{}, err
	}
	s.purgeSessionArtifacts(repoName, repoNameHash)

	if _, err := ensureHTTPSessionsRepoDir(s.cfg.DataDir, repoNameHash); err != nil {
		return CreateSessionResult{}, err
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return CreateSessionResult{}, err
	}
	token, err := generateSessionToken()
	if err != nil {
		return CreateSessionResult{}, err
	}
	tokenHash, err := hashToken(token)
	if err != nil {
		return CreateSessionResult{}, err
	}

	path, err := httpSessionPath(s.cfg.DataDir, repoNameHash, sessionID)
	if err != nil {
		return CreateSessionResult{}, err
	}
	now := s.nowUTC()
	rec := Record{
		Version:   SessionRecordVersion,
		Mode:      ModeHTTP,
		RepoName:  repoName,
		SessionID: sessionID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := writeSessionRecord(path, rec); err != nil {
		return CreateSessionResult{}, err
	}

	return CreateSessionResult{
		Mode:      ModeHTTP,
		RepoName:  rec.RepoName,
		SessionID: rec.SessionID,
		Token:     token,
		CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

func (s *service) ValidateCLISession(repoName string) error {
	if err := s.validateRepoName(repoName); err != nil {
		return err
	}
	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return err
	}
	path, err := cliSessionPath(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return err
	}

	rec, err := readSessionRecord(path)
	if err != nil {
		s.cleanupIfMalformed(path, err)
		return err
	}
	if rec.Mode != ModeCLI || rec.RepoName != repoName {
		_ = s.bestEffortRemove(path)
		return NewInvalidSessionError("session repository or mode mismatch", nil)
	}
	if s.isExpired(rec.ExpiresAt) {
		_ = s.bestEffortRemove(path)
		return NewSessionExpiredError("session expired", nil)
	}

	return nil
}

func (s *service) ValidateHTTPSession(repoName, token string) error {
	if err := s.validateRepoName(repoName); err != nil {
		return err
	}
	if token == "" {
		return NewInvalidArgumentError("token is required", nil)
	}
	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return err
	}

	paths, err := listHTTPSessionFiles(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return err
	}

	for _, path := range paths {
		rec, readErr := readSessionRecord(path)
		if readErr != nil {
			s.cleanupIfMalformed(path, readErr)
			continue
		}
		if rec.Mode != ModeHTTP || rec.RepoName != repoName {
			_ = s.bestEffortRemove(path)
			continue
		}
		if !tokenHashMatches(token, rec.TokenHash) {
			continue
		}

		if s.isExpired(rec.ExpiresAt) {
			_ = s.bestEffortRemove(path)
			return NewSessionExpiredError("session expired", nil)
		}

		return nil
	}

	return NewInvalidSessionError("session not found or token mismatch", nil)
}

func (s *service) RevokeCLISession(repoName string) error {
	if err := s.validateRepoName(repoName); err != nil {
		return err
	}
	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return err
	}
	path, err := cliSessionPath(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return err
	}

	removed, rmErr := s.removeIfPresent(path)
	if rmErr != nil {
		return rmErr
	}
	if !removed {
		s.purgeSessionArtifacts(repoName, repoNameHash)
		return nil
	}

	s.purgeSessionArtifacts(repoName, repoNameHash)

	return nil
}

func (s *service) RevokeHTTPSession(repoName, sessionID, token string) error {
	if err := s.validateRepoName(repoName); err != nil {
		return err
	}
	if sessionID == "" {
		return NewInvalidArgumentError("sessionID is required", nil)
	}
	if token == "" {
		return NewInvalidArgumentError("token is required", nil)
	}

	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return err
	}
	path, err := httpSessionPath(s.cfg.DataDir, repoNameHash, sessionID)
	if err != nil {
		return err
	}

	rec, err := readSessionRecord(path)
	if err != nil {
		if isSessionNotFound(err) {
			return nil
		}
		s.cleanupIfMalformed(path, err)
		return nil
	}

	if rec.Mode != ModeHTTP || rec.RepoName != repoName {
		_ = s.bestEffortRemove(path)
		return NewInvalidSessionError("session repository or mode mismatch", nil)
	}
	if !tokenHashMatches(token, rec.TokenHash) {
		return NewInvalidSessionError("session token mismatch", nil)
	}

	if _, err := s.removeIfPresent(path); err != nil {
		return err
	}
	s.purgeSessionArtifacts(repoName, repoNameHash)
	return nil
}

func (s *service) Cleanup(repoName string) (int, error) {
	if err := s.validateRepoName(repoName); err != nil {
		return 0, err
	}
	repoNameHash, err := hashRepoName(repoName)
	if err != nil {
		return 0, err
	}

	deleted := 0

	cliPath, err := cliSessionPath(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return 0, err
	}
	if rec, err := readSessionRecord(cliPath); err != nil {
		if !isSessionNotFound(err) {
			if removed, rmErr := s.removeIfPresent(cliPath); rmErr != nil {
				return deleted, rmErr
			} else if removed {
				deleted++
			}
		}
	} else if rec.Mode != ModeCLI || rec.RepoName != repoName || s.isExpired(rec.ExpiresAt) {
		if removed, rmErr := s.removeIfPresent(cliPath); rmErr != nil {
			return deleted, rmErr
		} else if removed {
			deleted++
		}
	}

	paths, err := listHTTPSessionFiles(s.cfg.DataDir, repoNameHash)
	if err != nil {
		return deleted, err
	}
	for _, path := range paths {
		rec, readErr := readSessionRecord(path)
		if readErr != nil {
			if removed, rmErr := s.removeIfPresent(path); rmErr != nil {
				return deleted, rmErr
			} else if removed {
				deleted++
			}
			continue
		}
		if rec.Mode != ModeHTTP || rec.RepoName != repoName || s.isExpired(rec.ExpiresAt) {
			if removed, rmErr := s.removeIfPresent(path); rmErr != nil {
				return deleted, rmErr
			} else if removed {
				deleted++
			}
		}
	}

	return deleted, nil
}

func (s *service) validateRepoName(repoName string) error {
	if repoName == "" {
		return NewInvalidArgumentError("repoName is required", nil)
	}
	if s.cfg.DataDir == "" {
		return NewInvalidArgumentError("dataDir is required", nil)
	}
	if s.cfg.SessionTTL <= 0 {
		return NewInvalidArgumentError("sessionTTL must be positive", nil)
	}
	return nil
}

func (s *service) ensureReady() error {
	return ensureSessionLayout(s.cfg.DataDir)
}

func (s *service) nowUTC() time.Time {
	if s.nowFn == nil {
		return time.Now().UTC()
	}
	return s.nowFn().UTC()
}

func (s *service) isExpired(expiresAt time.Time) bool {
	return !s.nowUTC().Before(expiresAt)
}

func (s *service) cleanupIfMalformed(path string, err error) {
	if isSessionNotFound(err) {
		return
	}
	if isSessionInvalid(err) {
		_ = s.bestEffortRemove(path)
	}
}

func (s *service) purgeSessionArtifacts(repoName, repoNameHash string) {
	cliPath, err := cliSessionPath(s.cfg.DataDir, repoNameHash)
	if err == nil {
		rec, readErr := readSessionRecord(cliPath)
		if readErr != nil {
			s.cleanupIfMalformed(cliPath, readErr)
		} else if rec.Mode != ModeCLI || rec.RepoName != repoName || s.isExpired(rec.ExpiresAt) {
			_ = s.bestEffortRemove(cliPath)
		}
	}

	paths, err := listHTTPSessionFiles(s.cfg.DataDir, repoNameHash)
	if err == nil {
		for _, p := range paths {
			rec, readErr := readSessionRecord(p)
			if readErr != nil {
				s.cleanupIfMalformed(p, readErr)
			} else if rec.Mode != ModeHTTP || rec.RepoName != repoName || s.isExpired(rec.ExpiresAt) {
				_ = s.bestEffortRemove(p)
			}
		}
	}
}

func (s *service) bestEffortRemove(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return NewDeleteFailedError("failed to delete session file", err)
	}
	return nil
}

func (s *service) removeIfPresent(path string) (bool, error) {
	if path == "" {
		return false, NewInvalidArgumentError("path is required", nil)
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, NewDeleteFailedError("failed to delete session file", err)
	}
	return true, nil
}

func isSessionInvalid(err error) bool {
	var e *common.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == ErrCodeInvalidSession
}

func isSessionNotFound(err error) bool {
	var e *common.Error
	if !errors.As(err, &e) {
		return false
	}
	if e.Code != ErrCodeInvalidSession {
		return false
	}
	return errors.Is(e.Err, os.ErrNotExist)
}
