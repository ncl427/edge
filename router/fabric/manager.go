/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package fabric

import (
	"bufio"
	"fmt"
	"github.com/kataras/go-events"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel"
	"github.com/openziti/edge/pb/edge_ctrl_pb"
	"github.com/openziti/edge/runner"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"math/rand"
	"sync"
	"time"
)

const (
	EventRemovedEdgeSession = "RemovedEdgeSession"

	EventAddedApiSession   = "AddedApiSession"
	EventUpdatedApiSession = "UpdatedApiSession"
	EventRemovedApiSession = "RemovedApiSession"
)

type RemoveListener func()

type DisconnectCB func(token string)

type StateManager interface {
	//"Network" Sessions
	RemoveEdgeSession(token string)
	AddEdgeSessionRemovedListener(token string, callBack func(token string)) RemoveListener

	//ApiSessions
	GetApiSession(token string) *edge_ctrl_pb.ApiSession
	GetApiSessionWithTimeout(token string, timeout time.Duration) *edge_ctrl_pb.ApiSession
	AddApiSession(apiSession *edge_ctrl_pb.ApiSession)
	UpdateApiSession(apiSession *edge_ctrl_pb.ApiSession)
	RemoveApiSession(token string)
	RemoveMissingApiSessions(knownSessions []*edge_ctrl_pb.ApiSession, beforeSessionId string)
	AddConnectedApiSession(token string)
	RemoveConnectedApiSession(token string)
	AddConnectedApiSessionWithChannel(token string, removeCB func(), ch channel.Channel)
	RemoveConnectedApiSessionWithChannel(token string, underlay channel.Channel)
	AddApiSessionRemovedListener(token string, callBack func(token string)) RemoveListener

	StartHeartbeat(channel channel.Channel, seconds int, closeNotify <-chan struct{})
	ValidateSessions(ch channel.Channel, chunkSize uint32, minInterval, maxInterval time.Duration)

	DumpApiSessions(c *bufio.ReadWriter) error
	MarkSyncInProgress(trackerId string)
	MarkSyncStopped(trackerId string)
	IsSyncInProgress() bool
}

type StateManagerImpl struct {
	apiSessionsByToken      cmap.ConcurrentMap[*edge_ctrl_pb.ApiSession]
	activeApiSessions       cmap.ConcurrentMap[*MapWithMutex]
	sessions                cmap.ConcurrentMap[uint32]
	recentlyRemovedSessions cmap.ConcurrentMap[time.Time]

	Hostname       string
	ControllerAddr string
	ClusterId      string
	NodeId         string
	events.EventEmmiter
	heartbeatRunner    runner.Runner
	heartbeatOperation *heartbeatOperation
	currentSync        string
	syncLock           sync.Mutex
}

func (sm *StateManagerImpl) MarkSyncInProgress(trackerId string) {
	sm.syncLock.Lock()
	defer sm.syncLock.Unlock()
	sm.currentSync = trackerId
}

func (sm *StateManagerImpl) MarkSyncStopped(trackerId string) {
	sm.syncLock.Lock()
	defer sm.syncLock.Unlock()
	if sm.currentSync == trackerId {
		sm.currentSync = ""
	}
}

func (sm *StateManagerImpl) IsSyncInProgress() bool {
	sm.syncLock.Lock()
	defer sm.syncLock.Unlock()
	return sm.currentSync == ""
}

func NewStateManager() StateManager {
	return &StateManagerImpl{
		EventEmmiter:            events.New(),
		apiSessionsByToken:      cmap.New[*edge_ctrl_pb.ApiSession](),
		activeApiSessions:       cmap.New[*MapWithMutex](),
		sessions:                cmap.New[uint32](),
		recentlyRemovedSessions: cmap.New[time.Time](),
	}
}

func (sm *StateManagerImpl) AddApiSession(apiSession *edge_ctrl_pb.ApiSession) {
	pfxlog.Logger().
		WithField("apiSessionId", apiSession.Id).
		WithField("apiSessionToken", apiSession.Token).
		WithField("apiSessionCertFingerprints", apiSession.CertFingerprints).
		Debugf("adding apiSession [id: %s] [token: %s] fingerprints [%s]", apiSession.Id, apiSession.Token, apiSession.CertFingerprints)
	sm.apiSessionsByToken.Set(apiSession.Token, apiSession)
	sm.Emit(EventAddedApiSession, apiSession)
}

func (sm *StateManagerImpl) UpdateApiSession(apiSession *edge_ctrl_pb.ApiSession) {
	pfxlog.Logger().
		WithField("apiSessionId", apiSession.Id).
		WithField("apiSessionToken", apiSession.Token).
		WithField("apiSessionCertFingerprints", apiSession.CertFingerprints).
		Debugf("updating apiSession [id: %s] [token: %s] fingerprints [%s]", apiSession.Id, apiSession.Token, apiSession.CertFingerprints)
	sm.apiSessionsByToken.Set(apiSession.Token, apiSession)
	sm.Emit(EventUpdatedApiSession, apiSession)
}

func (sm *StateManagerImpl) RemoveApiSession(token string) {
	if ns, ok := sm.apiSessionsByToken.Get(token); ok {
		pfxlog.Logger().WithField("apiSessionToken", token).Debugf("removing api session [token: %s]", token)
		sm.apiSessionsByToken.Remove(token)
		eventName := sm.getApiSessionRemovedEventName(token)
		sm.Emit(eventName)
		sm.RemoveAllListeners(eventName)
		sm.Emit(EventRemovedApiSession, ns)
	} else {
		pfxlog.Logger().WithField("apiSessionToken", token).Debugf("could not remove api session [token: %s]; not found", token)
	}
}

// RemoveMissingApiSessions removes API Sessions not present in the knownApiSessions argument. If the beforeSessionId
// value is not empty string, it will be used as a monotonic comparison between it and  API session ids. API session ids
// later than the sync will be ignored.
func (sm *StateManagerImpl) RemoveMissingApiSessions(knownApiSessions []*edge_ctrl_pb.ApiSession, beforeSessionId string) {
	validTokens := map[string]bool{}
	for _, apiSession := range knownApiSessions {
		validTokens[apiSession.Token] = true
	}

	var tokensToRemove []string
	sm.apiSessionsByToken.IterCb(func(token string, apiSession *edge_ctrl_pb.ApiSession) {
		if _, ok := validTokens[token]; !ok && (beforeSessionId == "" || apiSession.Id <= beforeSessionId) {
			tokensToRemove = append(tokensToRemove, token)
		}
	})

	for _, token := range tokensToRemove {
		sm.RemoveApiSession(token)
	}
}

func (sm *StateManagerImpl) RemoveEdgeSession(token string) {
	pfxlog.Logger().Debugf("removing network session [%s]", token)
	eventName := sm.getEdgeSessionRemovedEventName(token)
	sm.Emit(eventName)

	sm.RemoveAllListeners(eventName)
	sm.sessions.RemoveCb(token, func(key string, _ uint32, exists bool) bool {
		if exists {
			sm.recentlyRemovedSessions.Set(token, time.Now())
		}
		return true
	})

}

func (sm *StateManagerImpl) GetApiSessionWithTimeout(token string, timeout time.Duration) *edge_ctrl_pb.ApiSession {
	deadline := time.Now().Add(timeout)
	session := sm.GetApiSession(token)

	if session == nil {
		//convert this to return a channel instead of sleeping
		waitTime := time.Millisecond
		for time.Now().Before(deadline) {
			session = sm.GetApiSession(token)
			if session != nil {
				return session
			}
			time.Sleep(waitTime)
			if waitTime < time.Second {
				waitTime = waitTime * 2
			}
		}
	}
	return session
}

func (sm *StateManagerImpl) GetApiSession(token string) *edge_ctrl_pb.ApiSession {
	if apiSession, ok := sm.apiSessionsByToken.Get(token); ok {
		return apiSession
	}
	return nil
}

func (sm *StateManagerImpl) AddEdgeSessionRemovedListener(token string, callBack func(token string)) RemoveListener {
	if sm.recentlyRemovedSessions.Has(token) {
		callBack(token)
		return func() {}
	}

	sm.sessions.Upsert(token, 0, func(exist bool, valueInMap uint32, newValue uint32) uint32 {
		if !exist {
			return uint32(1)
		}
		return valueInMap + 1
	})

	eventName := sm.getEdgeSessionRemovedEventName(token)

	listener := func(args ...interface{}) {
		callBack(token)
	}
	sm.AddListener(eventName, listener)

	once := &sync.Once{}
	return func() {
		once.Do(func() {
			sm.SessionConnectionClosed(token)
			go sm.RemoveListener(eventName, listener) // likely to be called from Emit, which will cause a deadlock
		})
	}
}

func (sm *StateManagerImpl) SessionConnectionClosed(token string) {
	sm.sessions.Upsert(token, 0, func(exist bool, valueInMap uint32, newValue uint32) uint32 {
		if !exist {
			return uint32(0)
		}
		return valueInMap + 1
	})

	sm.sessions.RemoveCb(token, func(key string, v uint32, exists bool) bool {
		if !exists {
			return false
		}

		if v == 0 {
			sm.recentlyRemovedSessions.Set(token, time.Now())
			return true
		}

		return false
	})
}

func (sm *StateManagerImpl) AddApiSessionRemovedListener(token string, callBack func(token string)) RemoveListener {
	eventName := sm.getApiSessionRemovedEventName(token)
	listener := func(args ...interface{}) {
		callBack(token)
	}
	sm.AddListener(eventName, listener)

	return func() {
		go sm.RemoveListener(eventName, listener) // likely to be called from Emit, which will cause a deadlock
	}
}

func (sm *StateManagerImpl) getEdgeSessionRemovedEventName(token string) events.EventName {
	eventName := EventRemovedEdgeSession + "-" + token
	return events.EventName(eventName)
}

func (sm *StateManagerImpl) getApiSessionRemovedEventName(token string) events.EventName {
	eventName := EventRemovedApiSession + "-" + token
	return events.EventName(eventName)
}

func (sm *StateManagerImpl) StartHeartbeat(ctrl channel.Channel, intervalSeconds int, closeNotify <-chan struct{}) {
	sm.heartbeatOperation = newHeartbeatOperation(ctrl, time.Duration(intervalSeconds)*time.Second, sm)

	var err error
	sm.heartbeatRunner, err = runner.NewRunner(1*time.Second, 24*time.Hour, func(e error, operation runner.Operation) {
		pfxlog.Logger().WithError(err).Error("error during heartbeat runner")
	})

	if err != nil {
		pfxlog.Logger().WithError(err).Panic("could not create heartbeat runner")
	}

	if err := sm.heartbeatRunner.AddOperation(sm.heartbeatOperation); err != nil {
		pfxlog.Logger().WithError(err).Panic("could not add heartbeat operation to runner")
	}

	if err := sm.heartbeatRunner.Start(closeNotify); err != nil {
		pfxlog.Logger().WithError(err).Panic("could not start heartbeat runner")
	}

	pfxlog.Logger().Info("heartbeat starting")
}

func (sm *StateManagerImpl) AddConnectedApiSession(token string) {
	sm.activeApiSessions.Upsert(token, nil, func(exist bool, valueInMap *MapWithMutex, newValue *MapWithMutex) *MapWithMutex {
		if exist {
			return valueInMap
		}
		return newMapWithMutex()
	})
}

func (sm *StateManagerImpl) RemoveConnectedApiSession(token string) {
	sm.activeApiSessions.Remove(token)
}

func (sm *StateManagerImpl) AddConnectedApiSessionWithChannel(token string, removeCB func(), ch channel.Channel) {
	var sessions *MapWithMutex

	for sessions == nil {
		if sessions, _ = sm.activeApiSessions.Get(token); sessions != nil {
			sessions.Put(ch, removeCB)
		} else {
			sessions = newMapWithMutex()
			sessions.Put(ch, removeCB)
			if !sm.activeApiSessions.SetIfAbsent(token, sessions) {
				sessions = nil
			}
		}
	}
}

func (sm *StateManagerImpl) RemoveConnectedApiSessionWithChannel(token string, ch channel.Channel) {
	if sessions, ok := sm.activeApiSessions.Get(token); ok {
		if !ok {
			pfxlog.Logger().Panic("could not convert active sessions to map")
		}

		sessions.Lock()
		defer sessions.Unlock()

		if removeCB, found := sessions.m[ch]; found {
			removeCB()
			delete(sessions.m, ch)
		}

		if len(sessions.m) == 0 {
			sm.activeApiSessions.Remove(token)
		}
	}
}

func (sm *StateManagerImpl) ActiveApiSessionTokens() []string {
	return sm.activeApiSessions.Keys()
}

func (sm *StateManagerImpl) flushRecentlyRemoved() {
	now := time.Now()
	var toRemove []string
	sm.recentlyRemovedSessions.IterCb(func(key string, t time.Time) {
		remove := false

		if now.Sub(t) >= time.Minute {
			remove = true
		}

		if remove {
			toRemove = append(toRemove, key)
		}
	})

	for _, key := range toRemove {
		sm.recentlyRemovedSessions.Remove(key)
	}
}

func (sm *StateManagerImpl) DumpApiSessions(c *bufio.ReadWriter) error {
	ch := make(chan string, 15)

	go func() {
		defer close(ch)
		i := 0
		deadline := time.After(time.Second)
		timedOut := false

		for _, session := range sm.apiSessionsByToken.Items() {
			i++
			val := fmt.Sprintf("%v: id: %v, token: %v\n", i, session.Id, session.Token)
			select {
			case ch <- val:
			case <-deadline:
				timedOut = true
				break
			}
			if i%10000 == 0 {
				// allow a second to dump each 10k entries
				deadline = time.After(time.Second)
			}

		}

		if timedOut {
			select {
			case ch <- "timed out":
			case <-time.After(time.Second):
			}
		}
	}()

	for val := range ch {
		if _, err := c.WriteString(val); err != nil {
			return err
		}
	}
	return c.Flush()
}

func newMapWithMutex() *MapWithMutex {
	return &MapWithMutex{
		m: map[channel.Channel]func(){},
	}
}

type MapWithMutex struct {
	sync.Mutex
	m map[channel.Channel]func()
}

func (self *MapWithMutex) Put(ch channel.Channel, f func()) {
	self.Lock()
	defer self.Unlock()
	self.m[ch] = f
}

func (sm *StateManagerImpl) ValidateSessions(ch channel.Channel, chunkSize uint32, minInterval, maxInterval time.Duration) {
	sessionTokens := sm.sessions.Keys()

	for len(sessionTokens) > 0 {
		var chunk []string

		if len(sessionTokens) > int(chunkSize) {
			chunk = sessionTokens[:chunkSize]
			sessionTokens = sessionTokens[chunkSize:]
		} else {
			chunk = sessionTokens
			sessionTokens = nil
		}

		request := &edge_ctrl_pb.ValidateSessionsRequest{
			SessionTokens: chunk,
		}

		logrus.Debugf("validating edge sessions: %v", chunk)

		body, err := proto.Marshal(request)
		if err != nil {
			logrus.WithError(err).Error("failed to marshal validate sessions request")
			return
		}

		msg := channel.NewMessage(request.GetContentType(), body)
		if err := ch.Send(msg); err != nil {
			logrus.WithError(err).Error("failed to send validate sessions request")
			return
		}

		if len(sessionTokens) > 0 {
			interval := minInterval
			if minInterval < maxInterval {
				/* #nosec */
				delta := rand.Int63n(int64(maxInterval - minInterval))
				interval += minInterval + time.Duration(delta)
			}
			time.Sleep(interval)
		}
	}

}
