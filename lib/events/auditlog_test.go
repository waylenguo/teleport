/*
Copyright 2015-2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

// creates a file-based audit log and returns a proper *AuditLog pointer
// instead of the usual IAuditLog interface
func makeLog(t *testing.T, recordSessions bool) *AuditLog {
	t.Helper()
	return makeLogWithClock(t, recordSessions, nil)
}

// creates a file-based audit log and returns a proper *AuditLog pointer
// instead of the usual IAuditLog interface
func makeLogWithClock(t *testing.T, recordSessions bool, clock clockwork.Clock) *AuditLog {
	t.Helper()
	dataDir := t.TempDir()
	handler, err := NewLegacyHandler(LegacyHandlerConfig{
		Handler: NewMemoryUploader(),
		Dir:     dataDir,
	})
	if err != nil {
		t.Fatal(err)
		return nil
	}
	alog, err := NewAuditLog(AuditLogConfig{
		DataDir:        dataDir,
		RecordSessions: recordSessions,
		ServerID:       "server1",
		Clock:          clock,
		UIDGenerator:   utils.NewFakeUID(),
		UploadHandler:  handler,
	})
	if err != nil {
		t.Fatal(err)
		return nil
	}

	return alog
}

func TestNewAuditLog(t *testing.T) {
	al := makeLog(t, true)

	// close twice:
	require.NoError(t, al.Close())
	require.NoError(t, al.Close())
}

// TestSessionsOnOneAuthServer tests scenario when there are two auth servers
// and session is recorded on the first one
func TestSessionsOnOneAuthServer(t *testing.T) {
	dataDir := t.TempDir()
	fakeClock := clockwork.NewFakeClock()
	uploader := NewMemoryUploader()

	alog, err := NewAuditLog(AuditLogConfig{
		Clock:          fakeClock,
		DataDir:        dataDir,
		RecordSessions: true,
		ServerID:       "server1",
		UploadHandler:  uploader,
	})
	require.NoError(t, err)

	alog2, err := NewAuditLog(AuditLogConfig{
		Clock:          fakeClock,
		DataDir:        dataDir,
		RecordSessions: true,
		ServerID:       "server2",
		UploadHandler:  uploader,
	})
	require.NoError(t, err)

	uploadDir := t.TempDir()
	err = os.MkdirAll(filepath.Join(uploadDir, "upload", "sessions", apidefaults.Namespace), 0755)
	require.NoError(t, err)

	sessionID := string(session.NewID())

	err = alog.UploadSessionRecording(SessionRecording{
		Namespace: apidefaults.Namespace,
		SessionID: session.ID(sessionID),
		Recording: strings.NewReader("hello"),
	})
	require.NoError(t, err)

	upload(t, uploadDir, fakeClock, alog)

	// does not matter which audit server is accessed the results should be the same
	for _, a := range []*AuditLog{alog, alog2} {
		// read the session bytes
		history, err := a.GetSessionEvents(apidefaults.Namespace, session.ID(sessionID), 0, true)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// make sure offsets were properly set (0 for the first event and 5 bytes for hello):
		require.Equal(t, float64(0), history[1][SessionByteOffset])
		require.Equal(t, float64(0), history[1][SessionEventTimestamp])

		// fetch all bytes
		buff, err := a.GetSessionChunk(apidefaults.Namespace, session.ID(sessionID), 0, 5000)
		require.NoError(t, err)
		require.Equal(t, "hello", string(buff))

		// with offset
		buff, err = a.GetSessionChunk(apidefaults.Namespace, session.ID(sessionID), 2, 5000)
		require.NoError(t, err)
		require.Equal(t, "llo", string(buff))
	}
}

func upload(t *testing.T, uploadDir string, clock clockwork.Clock, auditLog IAuditLog) {
	t.Helper()

	// start uploader process
	eventsC := make(chan UploadEvent, 100)
	uploader, err := NewUploader(UploaderConfig{
		ServerID:   "upload",
		DataDir:    uploadDir,
		Clock:      clock,
		Namespace:  apidefaults.Namespace,
		Context:    context.TODO(),
		ScanPeriod: 100 * time.Millisecond,
		AuditLog:   auditLog,
		EventsC:    eventsC,
	})
	require.NoError(t, err)

	// scanner should upload the events
	err = uploader.Scan()
	require.NoError(t, err)

	select {
	case event := <-eventsC:
		require.NotNil(t, event)
		require.NoError(t, event.Error)
	case <-time.After(time.Second):
		require.FailNow(t, "Timeout waiting for the upload event")
	}
}

func TestSessionRecordingOff(t *testing.T) {
	now := time.Now().In(time.UTC).Round(time.Second)

	// create audit log with session recording disabled
	fakeClock := clockwork.NewFakeClockAt(now)

	alog, err := NewAuditLog(AuditLogConfig{
		Clock:          fakeClock,
		DataDir:        t.TempDir(),
		RecordSessions: false,
		ServerID:       "server1",
		UploadHandler:  NewMemoryUploader(),
	})
	require.NoError(t, err)

	username := "alice"
	sessionID := string(session.NewID())

	uploadDir := t.TempDir()
	err = os.MkdirAll(filepath.Join(uploadDir, "upload", "sessions", apidefaults.Namespace), 0755)
	require.NoError(t, err)

	// start the session and emit data stream to it
	firstMessage := []byte("hello")
	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionStart{
		UserMetadata: apievents.UserMetadata{User: username},
	}))
	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionPrint{
		Data: firstMessage,
	}))
	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionEnd{
		UserMetadata: apievents.UserMetadata{User: username},
	}))

	upload(t, uploadDir, fakeClock, alog)

	found, _, err := alog.SearchEvents(now.Add(-time.Hour), now.Add(time.Hour), apidefaults.Namespace, nil, 0, types.EventOrderAscending, "")
	require.NoError(t, err)
	require.Len(t, found, 3)

	eventA, okA := found[0].(*apievents.SessionStart)
	eventB, okB := found[1].(*apievents.SessionEnd)
	require.True(t, okA)
	require.True(t, okB)
	require.Equal(t, username, eventA.Login)
	require.Equal(t, username, eventB.Login)

	// inspect the session log, should have two events
	history, err := alog.GetSessionEvents(apidefaults.Namespace, session.ID(sessionID), 0, true)
	require.NoError(t, err)
	require.Len(t, history, 2)

	// try getting the session stream, should get an error
	_, err = alog.GetSessionChunk(apidefaults.Namespace, session.ID(sessionID), 0, 5000)
	require.Error(t, err)
}

func TestBasicLogging(t *testing.T) {
	clock := clockwork.NewFakeClock()
	alog := makeLogWithClock(t, true, clock)

	err := alog.EmitAuditEvent(context.Background(), &apievents.SessionJoin{
		SessionMetadata: apievents.SessionMetadata{SessionID: "1"},
		ServerMetadata:  apievents.ServerMetadata{ServerID: "2"},
	})
	require.NoError(t, err)

	logfile := alog.localLog.file.Name()
	require.NoError(t, alog.Close())

	bytes, err := os.ReadFile(logfile)
	require.NoError(t, err)
	t.Log(string(bytes))
	require.JSONEq(t, `{"ei":0,"event":"","time":"0001-01-01T00:00:00Z","sid":"1","server_id":"2"}`, string(bytes))
}

// TestLogRotation makes sure that logs are rotated
// on the day boundary and symlinks are created and updated
func TestLogRotation(t *testing.T) {
	start := time.Date(1984, time.April, 4, 0, 0, 0, 0, time.UTC)
	clock := clockwork.NewFakeClockAt(start)

	// create audit log, write a couple of events into it, close it
	alog := makeLogWithClock(t, true, clock)
	t.Cleanup(func() {
		require.NoError(t, alog.Close())
	})

	for _, duration := range []time.Duration{0, time.Hour * 25} {
		// advance time and emit audit event
		now := start.Add(duration)
		clock.Advance(duration)

		// emit regular event:
		event := &events.Resize{
			Metadata:     events.Metadata{Type: "resize", Time: now},
			TerminalSize: "10:10",
		}
		err := alog.EmitAuditEvent(context.TODO(), event)
		require.NoError(t, err)

		logfile := alog.localLog.file.Name()

		// make sure that file has the same date as the event
		dt, err := parseFileTime(filepath.Base(logfile))
		require.NoError(t, err)
		require.Equal(t, time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), dt)

		// read back what's been written:
		bytes, err := os.ReadFile(logfile)
		require.NoError(t, err)

		contents, err := json.Marshal(event)
		contents = append(contents, '\n')
		require.NoError(t, err)
		require.Equal(t, string(contents), string(bytes))

		// read back the contents using symlink
		bytes, err = os.ReadFile(filepath.Join(alog.localLog.SymlinkDir, SymlinkFilename))
		require.NoError(t, err)
		require.Equal(t, string(contents), string(bytes))

		found, _, err := alog.SearchEvents(now.Add(-time.Hour), now.Add(time.Hour), apidefaults.Namespace, nil, 0, types.EventOrderAscending, "")
		require.NoError(t, err)
		require.Len(t, found, 1)
	}
}

func TestUploadAndCompare(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	alog, err := NewAuditLog(AuditLogConfig{
		DataDir:        t.TempDir(),
		RecordSessions: true,
		Clock:          fakeClock,
		ServerID:       "remote",
		UploadHandler:  NewMemoryUploader(),
	})
	require.NoError(t, err)
	defer alog.Close()

	uploadAndCompare(t, fakeClock, alog)
}

// TestLegacyHandler tests playback for legacy sessions
// that are stored on disk in unpacked format
func TestLegacyHandler(t *testing.T) {
	dataDir := t.TempDir()
	memory := NewMemoryUploader()
	wrapper, err := NewLegacyHandler(LegacyHandlerConfig{
		Handler: memory,
		Dir:     dataDir,
	})
	require.NoError(t, err)

	fakeClock := clockwork.NewFakeClock()
	alog, err := NewAuditLog(AuditLogConfig{
		DataDir:        dataDir,
		RecordSessions: true,
		Clock:          fakeClock,
		ServerID:       "remote",
		UploadHandler:  wrapper,
	})
	require.NoError(t, err)

	defer alog.Close()

	sid, compare := uploadAndCompare(t, fakeClock, alog)

	// Download the session in the old format
	tarball, err := os.CreateTemp(t.TempDir(), "teleport-legacy")
	require.NoError(t, err)

	err = memory.Download(context.Background(), sid, tarball)
	require.NoError(t, err)

	authServers, err := getAuthServers(dataDir)
	require.NoError(t, err)
	require.Len(t, authServers, 1)

	targetDir := filepath.Join(dataDir, authServers[0], SessionLogsDir, apidefaults.Namespace)

	_, err = tarball.Seek(0, 0)
	require.NoError(t, err)

	err = utils.Extract(tarball, targetDir)
	require.NoError(t, err)

	unpacked, err := wrapper.IsUnpacked(context.Background(), sid)
	require.NoError(t, err)
	require.True(t, unpacked)

	// remove recording from the uploader
	// and make sure that playback for the session still
	// works
	memory.Reset()
	err = compare()
	require.NoError(t, err)
}

// TestExternalLog tests forwarding server and upload server case
func TestExternalLog(t *testing.T) {
	fileLog, err := NewFileLog(FileLogConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)

	fakeClock := clockwork.NewFakeClock()
	alog, err := NewAuditLog(AuditLogConfig{
		DataDir:        t.TempDir(),
		RecordSessions: true,
		Clock:          fakeClock,
		ServerID:       "remote",
		UploadHandler:  NewMemoryUploader(),
		ExternalLog:    fileLog,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, alog.Close())
	})

	uploadAndCompare(t, fakeClock, alog)
}

func uploadAndCompare(t *testing.T, fakeClock clockwork.Clock, alog IAuditLog) (session.ID, func() error) {
	uploadDir := t.TempDir()
	err := os.MkdirAll(filepath.Join(uploadDir, "upload", "sessions", apidefaults.Namespace), 0755)
	require.NoError(t, err)

	sessionID := session.NewID()

	// start the session and emit data stream to it and wrap it up
	firstMessage := []byte("hello")

	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionStart{
		UserMetadata:    apievents.UserMetadata{User: "bob"},
		SessionMetadata: apievents.SessionMetadata{SessionID: sessionID.String()},
	}))
	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionPrint{
		Metadata: apievents.Metadata{Index: 1},
		Data:     firstMessage,
	}))
	require.NoError(t, alog.EmitAuditEvent(context.Background(), &apievents.SessionEnd{
		Metadata:        apievents.Metadata{Index: 4},
		UserMetadata:    apievents.UserMetadata{User: "bob"},
		SessionMetadata: apievents.SessionMetadata{SessionID: sessionID.String()},
	}))

	upload(t, uploadDir, fakeClock, alog)

	compare := func() error {
		history, err := alog.GetSessionEvents(apidefaults.Namespace, sessionID, 0, true)
		if err != nil {
			return trace.Wrap(err)
		}
		if len(history) != 3 {
			return trace.BadParameter("expected history of 3, got %v", len(history))
		}

		// make sure offsets were properly set (0 for the first event and 5 bytes for hello):
		if history[1][SessionByteOffset].(float64) != float64(0) {
			return trace.BadParameter("expected offset of 0, got %v", history[1][SessionByteOffset])
		}
		if history[1][SessionEventTimestamp].(float64) != float64(0) {
			return trace.BadParameter("expected timestamp of 0, got %v", history[1][SessionEventTimestamp])
		}

		// fetch all bytes
		buff, err := alog.GetSessionChunk(apidefaults.Namespace, sessionID, 0, 5000)
		if err != nil {
			return trace.Wrap(err)
		}
		if string(buff) != string(firstMessage) {
			return trace.CompareFailed("%q != %q", string(buff), string(firstMessage))
		}

		// with offset
		buff, err = alog.GetSessionChunk(apidefaults.Namespace, sessionID, 2, 5000)
		if err != nil {
			return trace.Wrap(err)
		}
		if string(buff) != string(firstMessage[2:]) {
			return trace.CompareFailed("%q != %q", string(buff), string(firstMessage[2:]))
		}
		return nil
	}

	// trigger several parallel downloads, they should not fail
	iterations := 50
	resultsC := make(chan error, iterations)
	for i := 0; i < iterations; i++ {
		go func() {
			resultsC <- compare()
		}()
	}

	timeout := time.After(time.Second)
	for i := 0; i < iterations; i++ {
		select {
		case err := <-resultsC:
			require.NoError(t, err)
		case <-timeout:
			require.FailNow(t, "timeout waiting for goroutines to finish")
		}
	}

	return sessionID, compare
}

func marshal(f EventFields) []byte {
	data, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return data
}
